import json
import time
import uuid
from datetime import datetime
from pathlib import Path

from scapy.all import conf, get_if_addr, get_if_hwaddr, sendp
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff

from engine.arp_anchor import ARP_ANCHOR_FILTER, get_arp_anchor
from engine.periodic_counter import (
    PERIODIC_MODE,
    SYNCED_CLOCK_MODE,
    next_minute_epoch,
)

MDNS_GROUP_IP = "224.0.0.251"
MDNS_GROUP_MAC = "01:00:5e:00:00:fb"
MDNS_PORT = 5353
SIGNAL_SIGNATURE = "app=hcc-pointer-v1"
MESSAGE_CHUNK_SIZE = 200
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
        if counter_mode not in (PERIODIC_MODE, SYNCED_CLOCK_MODE):
            raise ValueError(f"unsupported counter mode: {counter_mode!r}")

        self.iface = iface if iface is not None else conf.iface
        self.message_bits = message_bits
        self.counter_mode = counter_mode
        self.session_id = uuid.uuid4().hex[:12]
        self.source_ip = get_if_addr(self.iface)
        self.source_mac = get_if_hwaddr(self.iface)
        self.output_file = Path(output_file)
        self.message_chunks = tuple(
            message_bits[start : start + MESSAGE_CHUNK_SIZE]
            for start in range(0, len(message_bits), MESSAGE_CHUNK_SIZE)
        )

        if self.source_ip == "0.0.0.0":
            raise RuntimeError(
                f"Interface {self.iface!r} has no usable IPv4 address; "
                "cannot send an mDNS pointer signal."
            )

    def _build_packet(self, attempt, event_id):
        sample_no = attempt["sample_no"]
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
            f"sample_no={sample_no}",
            f"counter_bits={sample_bits}",
        ]
        txt_fields.extend([
            f"window_index={window_index}",
            f"window_bits={window_bits}",
            f"compared_bits={compared_bits}",
            f"message_bit_length={len(self.message_bits)}",
        ])
        txt_fields.extend(
            f"message_bits_{index:03d}={chunk}"
            for index, chunk in enumerate(self.message_chunks)
        )

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

    def send_for_match(self, attempt):
        sample_no = attempt["sample_no"]
        event_id = (
            f"s{self.session_id}-t{sample_no}"
            f"-w{attempt['window_index']}"
        )
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

    def send_start_signal(self):
        print(
            "Sending startup mDNS arm before waiting for a broadcast ARP "
            "anchor...",
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
