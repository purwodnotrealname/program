import json
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import conf, get_if_addr, get_if_hwaddr, sendp
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import AsyncSniffer, sniff

from engine.arp_anchor import ARP_ANCHOR_FILTER, get_arp_anchor
from engine.periodic_counter import (
    GROUP_MODE,
    PERIODIC_MODE,
    SYNCED_CLOCK_MODE,
    UTC_COUNTER_MODES,
    UTC_POINTER_SEND_MAX_PHASE_SECONDS,
    UTC_POINTER_SEND_MIN_PHASE_SECONDS,
    UTC_START_LEAD_TICKS,
    UTC_TICK_PHASE_SECONDS,
    is_utc_minute_anchor_epoch,
    next_utc_minute_anchor_epoch,
    utc_tick_epoch,
)

MDNS_GROUP_IP = "224.0.0.251"
MDNS_GROUP_MAC = "01:00:5e:00:00:fb"
MDNS_PORT = 5353
SIGNAL_SIGNATURE = "app=hcc-pointer-v1"
SIGNAL_LOG_FILE = (
    Path(__file__).resolve().parents[2]
    / "engineDump"
    / "pointer_signals.json"
)


class PointerSignalSender:

    def __init__(
        self,
        iface=None,
        message_bits="",
        output_file=SIGNAL_LOG_FILE,
        counter_mode=PERIODIC_MODE,
    ):
        if not message_bits or any(bit not in "01" for bit in message_bits):
            raise ValueError("message_bits must be a non-empty binary string")
        if counter_mode not in (
            PERIODIC_MODE,
            SYNCED_CLOCK_MODE,
            *UTC_COUNTER_MODES,
        ):
            raise ValueError(f"unsupported counter mode: {counter_mode!r}")

        self.iface = iface if iface is not None else conf.iface
        self.message_bits = message_bits
        self.counter_mode = counter_mode
        self.session_id = uuid.uuid4().hex[:12]
        self.source_ip = get_if_addr(self.iface)
        self.source_mac = get_if_hwaddr(self.iface)
        self.output_file = Path(output_file)
        self._group_response_events = {}
        self._group_responses = {}
        self._group_response_lock = threading.Lock()
        self._group_response_sniffer = None
        self._active_group_response_key = None

        if self.source_ip == "0.0.0.0":
            raise RuntimeError(
                f"Interface {self.iface!r} has no usable IPv4 address; "
                "cannot send an mDNS pointer signal."
            )

    def _build_packet(self, attempt, event_id):
        window_index = attempt["window_index"]
        window_width = attempt["window_width"]
        window_bits = f"{attempt['window_value']:0{window_width}b}"
        counter_value = attempt["counter_value"]
        sample_bits = f"{counter_value:04b}"
        compared_bits = f"{attempt['compared_value']:0{window_width}b}"

        txt_fields = [
            SIGNAL_SIGNATURE,
            f"event_id={event_id}",
            f"counter_mode={self.counter_mode}",
            f"counter_bits={sample_bits}",
        ]
        txt_fields.extend([
            f"window_index={window_index}",
            f"window_bits={window_bits}",
            f"compared_bits={compared_bits}",
            f"message_bit_length={len(self.message_bits)}",
        ])
        if self.counter_mode == GROUP_MODE:
            txt_fields.extend([
                f"sender_session_id={self.session_id}",
                f"group_index={attempt['group_index']}",
                f"group_attempt={attempt['group_attempt']}",
                f"group_window_index={attempt['group_window_index']}",
                f"group_window_count={attempt['group_window_count']}",
                f"group_end={int(attempt['group_end'])}",
                f"group_start_tick_epoch={attempt['group_start_tick_epoch']}",
            ])
        if self.counter_mode in UTC_COUNTER_MODES:
            sample = attempt.get("sample")
            tick_epoch = (
                sample.get("clock_tick_epoch")
                if isinstance(sample, dict)
                else None
            )
            if isinstance(tick_epoch, bool) or not isinstance(tick_epoch, int):
                raise ValueError(
                    "UTC pointer requires the matched sample's tick epoch"
                )
            txt_fields.append(f"tick_epoch={tick_epoch}")

        return self._build_mdns_packet(event_id, txt_fields)

    def _build_mdns_packet(self, event_id, txt_fields):
        """Build the shared mDNS frame used by both pointer signal types."""
        instance_name = f"{event_id}._hcc-pointer._udp.local."
        answer = DNSRR(
            rrname=instance_name,
            type="TXT",
            cacheflush=1,
            ttl=120,
            rdata=[field.encode("ascii") for field in txt_fields],
        )
        return (
            Ether(src=self.source_mac, dst=MDNS_GROUP_MAC)
            / IP(src=self.source_ip, dst=MDNS_GROUP_IP, ttl=255)
            / UDP(sport=MDNS_PORT, dport=MDNS_PORT)
            / DNS(id=0, qr=1, aa=1, ancount=1, an=answer)
        )

    def _append_record(self, record):
        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        if self.output_file.exists():
            with self.output_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
            records = data.get("signals", []) if isinstance(data, dict) else []
        else:
            records = []

        records.append(record)
        with self.output_file.open("w", encoding="utf-8") as f:
            json.dump({"signals": records}, f, indent=2)

    def _send_packet(self, packet, record):
        try:
            sendp(packet, iface=self.iface, count=1, verbose=False)
        except Exception as exc:
            record["send_status"] = "failed"
            record["send_error"] = str(exc)
            self._append_record(record)
            raise

        self._append_record(record)

    def _observe_group_response(self, packet):
        """Queue a receiver control pointer for the active sender group."""
        if not (
            packet.haslayer(IP)
            and packet.haslayer(UDP)
            and packet.haslayer(DNS)
            and packet[IP].src != self.source_ip
            and packet[IP].dst == MDNS_GROUP_IP
            and packet[UDP].sport == MDNS_PORT
            and packet[UDP].dport == MDNS_PORT
        ):
            return

        dns = packet[DNS]
        if not dns.qr or not dns.aa or not dns.ancount:
            return
        answer = dns.an
        for _ in range(int(dns.ancount)):
            if not hasattr(answer, "rrname"):
                break
            name = answer.rrname
            if isinstance(name, bytes):
                name = name.decode("utf-8", errors="replace")
            if (
                int(answer.type) == 16
                and str(name).rstrip(".").lower().endswith(
                    "_hcc-pointer._udp.local"
                )
            ):
                rdata = answer.rdata
                fields = rdata if isinstance(rdata, (list, tuple)) else [rdata]
                values = []
                for field in fields:
                    if isinstance(field, bytes):
                        field = field.decode("utf-8", errors="replace")
                    values.append(str(field).strip())
                metadata = {}
                for field in values:
                    if "=" in field:
                        key, value = field.split("=", 1)
                        metadata[key] = value
                if (
                    SIGNAL_SIGNATURE in values
                    and metadata.get("counter_mode") == GROUP_MODE
                    and metadata.get("signal_type")
                    in ("group_complete", "group_replay")
                    and metadata.get("target_session_id") == self.session_id
                ):
                    try:
                        key = (
                            int(metadata["group_index"]),
                            int(metadata["group_attempt"]),
                        )
                        resume_at_epoch = int(metadata["resume_at_epoch"])
                        next_group_index = int(metadata["next_group_index"])
                        next_group_attempt = int(
                            metadata["next_group_attempt"]
                        )
                    except (KeyError, ValueError):
                        return
                    final_group = metadata.get("final_group") == "1"
                    if (
                        key[0] < 0
                        or key[1] < 1
                        or next_group_index < 0
                        or next_group_attempt < 1
                        or (
                            not final_group
                            and not is_utc_minute_anchor_epoch(
                                resume_at_epoch
                            )
                        )
                    ):
                        return
                    response = {
                        "action": metadata["signal_type"].replace(
                            "group_", ""
                        ),
                        "resume_at_epoch": resume_at_epoch,
                        "receiver_session_id": metadata.get(
                            "receiver_session_id"
                        ),
                        "group_index": key[0],
                        "group_attempt": key[1],
                        "next_group_index": next_group_index,
                        "next_group_attempt": next_group_attempt,
                        "final_group": final_group,
                    }
                    with self._group_response_lock:
                        active_key = self._active_group_response_key
                        response_event = self._group_response_events.get(
                            active_key
                        )
                        next_key = (next_group_index, next_group_attempt)
                        if (
                            response_event is not None
                            and active_key is not None
                            and next_key > active_key
                        ):
                            self._group_responses[active_key] = response
                            response_event.set()
                return
            answer = answer.payload

    def _start_group_response_listener(self):
        if (
            self.counter_mode != GROUP_MODE
            or self._group_response_sniffer is not None
        ):
            return
        started = threading.Event()
        self._group_response_sniffer = AsyncSniffer(
            iface=self.iface,
            filter=f"udp and dst host {MDNS_GROUP_IP} and dst port {MDNS_PORT}",
            prn=self._observe_group_response,
            store=False,
            started_callback=started.set,
        )
        self._group_response_sniffer.start()
        if not started.wait(timeout=5):
            self._group_response_sniffer.stop()
            self._group_response_sniffer = None
            raise RuntimeError(
                "Sender group-response listener did not start in 5 seconds"
            )

    def start_group_attempt(self, group_index, group_attempt):
        """Register the active attempt before a group or replay begins."""
        if self.counter_mode != GROUP_MODE:
            return
        key = (group_index, group_attempt)
        with self._group_response_lock:
            previous_key = self._active_group_response_key
            if previous_key is not None and previous_key != key:
                self._group_response_events.pop(previous_key, None)
                self._group_responses.pop(previous_key, None)
            self._group_response_events[key] = threading.Event()
            self._group_responses.pop(key, None)
            self._active_group_response_key = key

    def group_response_received(self, group_index, group_attempt):
        """Report whether a receiver response arrived for this attempt."""
        with self._group_response_lock:
            response_event = self._group_response_events.get(
                (group_index, group_attempt)
            )
        return (
            response_event.is_set()
            if response_event is not None
            else False
        )

    def wait_for_group_response(
        self,
        group_index,
        group_attempt,
        group_window_count,
        message_bit_length,
    ):
        """Wait for the receiver's one-time completion or replay pointer."""
        if self.counter_mode != GROUP_MODE:
            return None

        group_key = (group_index, group_attempt)
        with self._group_response_lock:
            response_event = self._group_response_events.get(group_key)
            if response_event is None:
                response_event = threading.Event()
                self._group_response_events[group_key] = response_event
                self._active_group_response_key = group_key
        print(
            f"Group {group_index + 1} sent ({group_window_count} windows); "
            "sender counter is paused until the receiver replies.",
            flush=True,
        )
        while not response_event.wait(0.5):
            pass

        with self._group_response_lock:
            response = self._group_responses.get(group_key)
        if response is None:
            raise RuntimeError("Receiver control pointer had no parsed response")
        if response["action"] == "complete":
            print(
                "Receiver confirmed group "
                f"{response['group_index'] + 1} complete.",
                flush=True,
            )
        else:
            print(
                f"Receiver requested group "
                f"{response['next_group_index'] + 1}, attempt "
                f"{response['next_group_attempt']}.",
                flush=True,
            )
        return response

    def send_for_match(self, attempt):
        if self.counter_mode in UTC_COUNTER_MODES:
            while True:
                now = time.time()
                phase = now - int(now)
                if (
                    UTC_POINTER_SEND_MIN_PHASE_SECONDS
                    <= phase
                    <= UTC_POINTER_SEND_MAX_PHASE_SECONDS
                ):
                    break
                if phase < UTC_POINTER_SEND_MIN_PHASE_SECONDS:
                    delay = UTC_POINTER_SEND_MIN_PHASE_SECONDS - phase
                else:
                    delay = (
                        1.0
                        - phase
                        + UTC_POINTER_SEND_MIN_PHASE_SECONDS
                    )
                time.sleep(delay)

        sample_no = attempt["sample_no"]
        if self.counter_mode == GROUP_MODE:
            event_id = (
                f"s{self.session_id}-g{attempt['group_index'] + 1}"
                f"-a{attempt['group_attempt']}-w{attempt['window_index']}"
            )
        else:
            event_id = f"s{self.session_id}-w{attempt['window_index']}"
        packet = self._build_packet(attempt, event_id)
        record = {
            "event_id": event_id,
            "session_id": self.session_id,
            "timestamp": datetime.now().isoformat(timespec="milliseconds"),
            "interface": self.iface,
            "source_ip": self.source_ip,
            "source_mac": self.source_mac,
            "destination_ip": MDNS_GROUP_IP,
            "destination_port": MDNS_PORT,
            "counter_mode": self.counter_mode,
            "counter_identity": {
                "sample_no": sample_no,
                "window_index": attempt["window_index"],
            },
            "message_bits": self.message_bits,
            "message_bit_length": len(self.message_bits),
            "match": attempt,
            "wire_frame_hex": bytes(packet).hex(),
            "send_status": "sent",
        }

        self._send_packet(packet, record)
        print(
            f"       - mDNS pointer multicast sent for {event_id} "
            f"({len(self.message_bits)} message bits)"
        )
        return None

    def send_start_signal(self):
        self._start_group_response_listener()
        if self.counter_mode == SYNCED_CLOCK_MODE:
            print(
                "Synchronized clock mode: sniffing for a broadcast ARP "
                "directly; no startup mDNS arm will be sent.",
                flush=True,
            )
        else:
            if self.counter_mode == GROUP_MODE:
                print(
                    "Sending startup mDNS arm with the next UTC :00 anchor, "
                    "then waiting for broadcast ARP...",
                    flush=True,
                )
                return self._send_group_startup_arm_and_wait_arp()
            print(
                "Sending startup mDNS arm before waiting for a broadcast "
                "ARP anchor...",
                flush=True,
            )
            arm_event_id = f"s{self.session_id}-periodic-arm"
            arm_packet = self._build_mdns_packet(
                arm_event_id,
                [
                    SIGNAL_SIGNATURE,
                    f"event_id={arm_event_id}",
                    f"counter_mode={self.counter_mode}",
                    "signal_type=arm",
                ],
            )
            arm_record = {
                "event_id": arm_event_id,
                "session_id": self.session_id,
                "timestamp": datetime.now().isoformat(timespec="milliseconds"),
                "interface": self.iface,
                "source_ip": self.source_ip,
                "source_mac": self.source_mac,
                "destination_ip": MDNS_GROUP_IP,
                "destination_port": MDNS_PORT,
                "counter_mode": self.counter_mode,
                "signal_type": "arm",
                "wire_frame_hex": bytes(arm_packet).hex(),
                "send_status": "sent",
            }
            self._send_packet(arm_packet, arm_record)
            print(f"Startup mDNS arm sent for {arm_event_id}", flush=True)

        print("Waiting for a broadcast ARP frame...", flush=True)
        anchor_observed_at = []

        def record_anchor_observation(_packet):
            if not anchor_observed_at:
                anchor_observed_at.append((time.perf_counter(), time.time()))

        anchor_packets = sniff(
            iface=self.iface,
            filter=ARP_ANCHOR_FILTER,
            count=1,
            store=True,
            prn=record_anchor_observation,
        )
        if not anchor_packets:
            raise RuntimeError("No broadcast ARP anchor was captured.")
        if not anchor_observed_at:
            raise RuntimeError("Could not timestamp the ARP anchor observation.")
        anchor = get_arp_anchor(anchor_packets[0])
        if anchor is None:
            raise RuntimeError("Captured ARP frame is not a valid broadcast anchor.")

        print(
            f"ARP anchor observed ({anchor['src_ip']} -> {anchor['target_ip']}, "
            f"id={anchor['anchor_id']}).",
            flush=True,
        )
        anchor_perf_counter, anchor_wallclock = anchor_observed_at[0]
        start_at_epoch = None
        if self.counter_mode == SYNCED_CLOCK_MODE:
            start_at_epoch = next_minute_epoch(anchor_wallclock)
        elif self.counter_mode in UTC_COUNTER_MODES:
            start_at_epoch = (
                utc_tick_epoch(anchor_wallclock) + UTC_START_LEAD_TICKS
            )

        event_id = f"s{self.session_id}-periodic-start"
        start_fields = [
            SIGNAL_SIGNATURE,
            f"event_id={event_id}",
            f"counter_mode={self.counter_mode}",
            "signal_type=start",
            f"anchor_id={anchor['anchor_id']}",
        ]
        if start_at_epoch is not None:
            start_fields.append(f"start_at_epoch={start_at_epoch}")
        packet = self._build_mdns_packet(
            event_id,
            start_fields,
        )
        record = {
            "event_id": event_id,
            "session_id": self.session_id,
            "timestamp": datetime.now().isoformat(timespec="milliseconds"),
            "interface": self.iface,
            "source_ip": self.source_ip,
            "source_mac": self.source_mac,
            "destination_ip": MDNS_GROUP_IP,
            "destination_port": MDNS_PORT,
            "counter_mode": self.counter_mode,
            "signal_type": "start",
            "arp_anchor": anchor,
            "wire_frame_hex": bytes(packet).hex(),
            "send_status": "sent",
        }
        if start_at_epoch is not None:
            record["start_at_epoch"] = start_at_epoch
        self._send_packet(packet, record)
        if self.counter_mode in UTC_COUNTER_MODES:
            start_at = datetime.fromtimestamp(
                start_at_epoch + UTC_TICK_PHASE_SECONDS
            ).isoformat(timespec="milliseconds")
            print(
                f"Startup pointer sent for {event_id}; both UTC counters "
                f"will begin at {start_at}.",
                flush=True,
            )
            return start_at_epoch
        if start_at_epoch is not None:
            start_at = datetime.fromtimestamp(start_at_epoch).isoformat(
                timespec="seconds"
            )
            print(
                f"Startup pointer sent for {event_id}; synchronized counter "
                f"will start at {start_at}.",
                flush=True,
            )
            return start_at_epoch
        print(f"Startup pointer sent for {event_id}")
        return anchor_perf_counter

    def _send_group_startup_arm_and_wait_arp(self):
        """Announce the shared UTC start epoch before both sides observe ARP."""
        while True:
            start_at_epoch = next_utc_minute_anchor_epoch(time.time())
            arm_event_id = f"s{self.session_id}-group-arm-{start_at_epoch}"
            fields = [
                SIGNAL_SIGNATURE,
                f"event_id={arm_event_id}",
                f"counter_mode={GROUP_MODE}",
                "signal_type=arm",
                f"sender_session_id={self.session_id}",
                f"message_bit_length={len(self.message_bits)}",
                f"start_at_epoch={start_at_epoch}",
            ]
            packet = self._build_mdns_packet(arm_event_id, fields)
            record = {
                "event_id": arm_event_id,
                "session_id": self.session_id,
                "timestamp": datetime.now().isoformat(timespec="milliseconds"),
                "interface": self.iface,
                "source_ip": self.source_ip,
                "source_mac": self.source_mac,
                "destination_ip": MDNS_GROUP_IP,
                "destination_port": MDNS_PORT,
                "counter_mode": GROUP_MODE,
                "signal_type": "arm",
                "message_bit_length": len(self.message_bits),
                "start_at_epoch": start_at_epoch,
                "wire_frame_hex": bytes(packet).hex(),
                "send_status": "sent",
            }
            self._send_packet(packet, record)
            print(
                f"Startup arm sent; both sides will use the next UTC :00 anchor "
                f"{start_at_epoch}. Waiting for broadcast ARP...",
                flush=True,
            )

            anchor_observed_at = []

            def record_anchor_observation(_packet):
                if not anchor_observed_at:
                    anchor_observed_at.append((time.perf_counter(), time.time()))

            anchor_packets = sniff(
                iface=self.iface,
                filter=ARP_ANCHOR_FILTER,
                count=1,
                store=True,
                prn=record_anchor_observation,
            )
            if not anchor_packets or not anchor_observed_at:
                raise RuntimeError("No broadcast ARP anchor was captured.")
            anchor = get_arp_anchor(anchor_packets[0])
            if anchor is None:
                raise RuntimeError("Captured ARP frame is not a valid broadcast anchor.")

            _anchor_perf_counter, anchor_wallclock = anchor_observed_at[0]
            if start_at_epoch <= utc_tick_epoch(anchor_wallclock):
                print(
                    "The shared UTC start epoch passed before ARP arrived; "
                    "sending a fresh startup arm and waiting for another ARP.",
                    flush=True,
                )
                continue

            anchor_utc = datetime.fromtimestamp(
                start_at_epoch, timezone.utc
            ).isoformat(timespec="seconds")
            print(
                f"ARP anchor observed ({anchor['src_ip']} -> "
                f"{anchor['target_ip']}, id={anchor['anchor_id']}). "
                f"Waiting for UTC :00 anchor {anchor_utc}; no post-ARP "
                "start pointer is sent.",
                flush=True,
            )
            return start_at_epoch

    def close(self):
        if self._group_response_sniffer is not None:
            if self._group_response_sniffer.running:
                self._group_response_sniffer.stop()
            self._group_response_sniffer.join()
            self._group_response_sniffer = None
        with self._group_response_lock:
            self._group_response_events.clear()
            self._group_responses.clear()
            self._active_group_response_key = None
