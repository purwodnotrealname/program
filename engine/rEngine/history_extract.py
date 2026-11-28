"""Tangkap anchor ARP dan pointer Periodic-B untuk menghubungkan counter."""

import json
import queue
import threading
import time
import uuid
from collections import OrderedDict
from datetime import datetime

from scapy.all import get_if_addr, get_if_hwaddr, sendp
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import AsyncSniffer

from engine.arp_anchor import ARP_ANCHOR_FILTER, get_arp_anchor
from engine.interface_utils import describe_interface
from engine.periodic_counter import (
    GROUP_MODE,
    GROUP_RETRY_TIMEOUT_SECONDS,
    GROUP_WINDOW_COUNT,
    OUTPUT_BITS,
    PERIODIC_COUNTER_INTERVAL_SECONDS,
    PERIODIC_MODE,
    SYNCED_CLOCK_MODE,
    UTC_COUNTER_MODES,
    UTC_TICK_PHASE_SECONDS,
    PeriodicCounterState,
    counter_for_utc_tick,
    timestamp_now,
    utc_tick_epoch,
)
from engine.pointer_protocol import (
    MDNS_GROUP_IP,
    MDNS_GROUP_MAC,
    MDNS_PORT,
    POINTER_TXT_SIGNATURE,
)
from .history_buffer import ReceiverHistoryStore
from .pointer_recognition import PointerRecognizer
from .secret_bits import ReceiverSecretBitsStore


# Receiver menangkap anchor ARP dan pointer; counter dibuat lokal per interval.
POINTER_FILTER = (
    f"(udp and dst port {MDNS_PORT} and dst host {MDNS_GROUP_IP})"
)
CAPTURE_FILTER = f"({ARP_ANCHOR_FILTER} or {POINTER_FILTER})"
POINTER_IDLE_COUNTER_SAMPLES = 32


class ReceiverHistoryExtractor:
    """Kelola start-pointer, sampling periodik, dan pointer data."""

    def __init__(
        self,
        iface,
        buffer_path,
        log_path,
        secret_bits_path,
        pointer_source_ip,
        counter_mode=PERIODIC_MODE,
    ):
        """Hubungkan recognizer, buffer, dan penyimpan secret untuk satu interface."""
        if counter_mode not in (
            PERIODIC_MODE,
            SYNCED_CLOCK_MODE,
            *UTC_COUNTER_MODES,
        ):
            raise ValueError(
                "Receiver supports legacy, synchronized clock, UTC, "
                "or UTC group mode"
            )
        self.iface = iface
        self.counter_mode = counter_mode
        self.store = ReceiverHistoryStore(
            buffer_path,
            log_path,
            counter_mode=counter_mode,
        )
        self.secret_bits_store = ReceiverSecretBitsStore(secret_bits_path)
        self.pointer_recognizer = PointerRecognizer(pointer_source_ip)
        self.session_id = uuid.uuid4().hex
        self.sample_count = 0
        self.captured_packet_count = 0
        self.recognized_pointer_count = 0
        self.recognition_rejections = {}
        self._counter_state = PeriodicCounterState()
        self._next_periodic_tick = None
        self._next_periodic_tick_epoch = None
        self._next_utc_tick_epoch = None
        self._utc_start_tick_epoch = None
        self._startup_armed = counter_mode == SYNCED_CLOCK_MODE
        self._start_pointer_seen = False
        self._pending_start = None
        self._last_pointer_sample_count = None
        self._stop_requested = threading.Event()
        self._observed_arp_anchors = OrderedDict()
        self._group_retry_pending = False
        self._group_sender_session_id = None
        self._final_group_complete = False
        self._group_attempt_start_epochs = {}
        self._observed_arp_anchor_perf_counters = {}
        self._queue = queue.Queue()
        self._worker = None

    def _on_sniff_packet(self, packet):
        """Antrekan frame dengan waktu kedatangannya agar worker menjaga urutan event."""
        self.captured_packet_count += 1
        arrival_perf_counter = time.perf_counter()
        try:
            capture_timestamp = float(packet.time)
            wallclock = datetime.fromtimestamp(capture_timestamp).isoformat(
                timespec="milliseconds"
            )
        except (AttributeError, TypeError, ValueError, OverflowError, OSError):
            capture_timestamp = time.time()
            wallclock = datetime.now().isoformat(timespec="milliseconds")
        self._queue.put(
            (packet, wallclock, arrival_perf_counter, capture_timestamp)
        )

    def _record_periodic_value(self, clock_tick_epoch=None):
        """Buat satu nilai counter, simpan ke buffer, dan tulis ke log receiver."""
        self.sample_count += 1
        if self.counter_mode in UTC_COUNTER_MODES and clock_tick_epoch is not None:
            if self._utc_start_tick_epoch is None:
                raise RuntimeError("UTC start tick has not been initialized")
            counter = counter_for_utc_tick(
                clock_tick_epoch,
                self._utc_start_tick_epoch,
            )
        else:
            counter = self._counter_state.next_value()
        counter_bits = f"{counter:0{OUTPUT_BITS}b}"
        record = {
            "session_id": self.session_id,
            "sample_no": self.sample_count,
            "protocol": "PERIODIC",
            "counter_mode": self.counter_mode,
            "timestamp": timestamp_now(),
            "counter": counter,
            "counter_bits": counter_bits,
        }
        if clock_tick_epoch is not None:
            record["clock_tick_epoch"] = clock_tick_epoch
        self.store.add(record)
        print(
            f"[{self.sample_count:04d}] PERIODIC counter={counter:02d} "
            f"- bits={counter_bits} "
            f"(buffer {len(self.store.newest_first)}/"
            f"{self.store.capacity})",
            flush=True,
        )

    def _check_pointer_idle_timeout(self):
        """Handle the group replay timeout or stop ordinary receiver modes."""
        if self._last_pointer_sample_count is None:
            return
        idle_samples = self.sample_count - self._last_pointer_sample_count
        if self.counter_mode == GROUP_MODE:
            if self._final_group_complete:
                return
            if idle_samples <= GROUP_RETRY_TIMEOUT_SECONDS:
                return
            self._group_retry_pending = True
            self.store.append_event({
                "event_type": "group_replay_expected",
                "session_id": self.session_id,
                "timestamp": timestamp_now(),
                "idle_counter_samples": idle_samples,
                "silence_threshold_seconds": GROUP_RETRY_TIMEOUT_SECONDS,
                "action": "retain received windows and accept replayed group",
            })
            print(
                f"No pointer for more than {GROUP_RETRY_TIMEOUT_SECONDS} "
                "seconds; retaining received windows and waiting for the "
                "sender to replay this group.",
                flush=True,
            )
            self._last_pointer_sample_count = self.sample_count
            return

        if idle_samples >= POINTER_IDLE_COUNTER_SAMPLES:
            print(
                f"No data pointer received for "
                f"{POINTER_IDLE_COUNTER_SAMPLES} counter attempts; "
                "stopping receiver.",
                flush=True,
            )
            self._stop_requested.set()

    def _emit_due_periodic_values(self, now_perf_counter, now_epoch=None):
        """Keluarkan sampel yang jadwal intervalnya sudah tiba."""
        if self.counter_mode in UTC_COUNTER_MODES:
            if (
                self._next_utc_tick_epoch is None
                or self._stop_requested.is_set()
            ):
                return
            if now_epoch is None:
                now_epoch = time.time()
            due_tick_epoch = utc_tick_epoch(now_epoch)
            while (
                self._next_utc_tick_epoch <= due_tick_epoch
                and not self._stop_requested.is_set()
            ):
                tick_epoch = self._next_utc_tick_epoch
                self._record_periodic_value(clock_tick_epoch=tick_epoch)
                self._next_utc_tick_epoch += 1
                self._check_pointer_idle_timeout()
            return

        while (
            self._next_periodic_tick is not None
            and now_perf_counter >= self._next_periodic_tick
            and not self._stop_requested.is_set()
        ):
            next_tick = self._next_periodic_tick + PERIODIC_COUNTER_INTERVAL_SECONDS
            tick_epoch = self._next_periodic_tick_epoch
            self._record_periodic_value(clock_tick_epoch=tick_epoch)
            self._next_periodic_tick = next_tick
            if tick_epoch is not None:
                self._next_periodic_tick_epoch = tick_epoch + int(
                    PERIODIC_COUNTER_INTERVAL_SECONDS
                )
            self._check_pointer_idle_timeout()

    def _record_start_pointer(
        self,
        pointer_record,
        timestamp,
        anchor_perf_counter,
        now_perf_counter,
        start_at_epoch=None,
    ):
        """Schedule counter ticks from the matched ARP observation time."""
        self._start_pointer_seen = True
        if self.counter_mode == GROUP_MODE:
            self._last_pointer_sample_count = self.sample_count
        if self.counter_mode == SYNCED_CLOCK_MODE:
            if (
                isinstance(start_at_epoch, bool)
                or not isinstance(start_at_epoch, int)
                or start_at_epoch % 60 != 0
            ):
                raise ValueError(
                    "Synchronized start time must be an integer minute boundary"
                )
            self._next_periodic_tick = time.perf_counter() + max(
                0.0, start_at_epoch - time.time()
            )
            self._next_periodic_tick_epoch = start_at_epoch
        elif self.counter_mode in UTC_COUNTER_MODES:
            if (
                isinstance(start_at_epoch, bool)
                or not isinstance(start_at_epoch, int)
            ):
                raise ValueError(
                    "UTC startup pointer has no shared start tick epoch"
                )
            self._utc_start_tick_epoch = start_at_epoch
            self._next_utc_tick_epoch = start_at_epoch
            self._next_periodic_tick = None
            self._next_periodic_tick_epoch = None
        else:
            self._next_periodic_tick = anchor_perf_counter
            self._next_periodic_tick_epoch = None
        start_event = {
            "event_type": "periodic_b_start_pointer",
            "session_id": self.session_id,
            "protocol": "mDNS",
            "counter_mode": self.counter_mode,
            "timestamp": timestamp,
            "anchor_id": pointer_record.get("anchor_id"),
            "arp_anchor": self._observed_arp_anchors.get(
                pointer_record.get("anchor_id")
            ),
            **pointer_record,
        }
        if start_at_epoch is not None:
            start_event["start_at_epoch"] = start_at_epoch
        self.store.append_event(start_event)
        if self.counter_mode in UTC_COUNTER_MODES:
            start_at = datetime.fromtimestamp(
                start_at_epoch + UTC_TICK_PHASE_SECONDS
            ).isoformat(timespec="milliseconds")
            print(
                "Startup pointer matched its ARP anchor; both UTC counters "
                f"will start at {start_at}.",
                flush=True,
            )
        elif start_at_epoch is None:
            print(
                "Periodic-B startup pointer matched the observed ARP anchor; "
                "counter started.",
                flush=True,
            )
        else:
            start_at = datetime.fromtimestamp(start_at_epoch).isoformat(
                timespec="seconds"
            )
            print(
                "Startup pointer matched its ARP anchor; synchronized counter "
                f"will start at {start_at}.",
                flush=True,
            )
        self._emit_due_periodic_values(now_perf_counter, time.time())

    def _record_arm_pointer(self, pointer_record, timestamp):
        """Arm the receiver so only later ARP frames can anchor this run."""
        if self.counter_mode == SYNCED_CLOCK_MODE:
            self._note_recognition_rejection(
                "startup mDNS arm is not used in synchronized clock mode"
            )
            return
        if self._start_pointer_seen:
            return
        self._startup_armed = True
        self._pending_start = None
        self._observed_arp_anchors.clear()
        self._observed_arp_anchor_perf_counters.clear()
        self.store.append_event({
            "event_type": "periodic_b_arm_pointer",
            "session_id": self.session_id,
            "protocol": "mDNS",
            "counter_mode": self.counter_mode,
            "timestamp": timestamp,
            **pointer_record,
        })
        print(
            "Startup mDNS arm received; waiting for a broadcast ARP anchor.",
            flush=True,
        )

    def _observe_arp_anchor(self, packet, timestamp, arrival_perf_counter):
        """Remember recent broadcast ARP frames so start can match its anchor."""
        anchor = get_arp_anchor(packet)
        if anchor is None:
            return False

        if not self._startup_armed or self._start_pointer_seen:
            return True

        anchor_id = anchor["anchor_id"]
        if anchor_id not in self._observed_arp_anchors:
            anchor["observed_at"] = timestamp
            self._observed_arp_anchors[anchor_id] = anchor
            self._observed_arp_anchor_perf_counters[anchor_id] = (
                arrival_perf_counter
            )
        self._observed_arp_anchors.move_to_end(anchor_id)
        while len(self._observed_arp_anchors) > 128:
            expired_anchor_id, _ = self._observed_arp_anchors.popitem(
                last=False
            )
            self._observed_arp_anchor_perf_counters.pop(
                expired_anchor_id, None
            )

        if self._pending_start is not None:
            (
                pointer_record,
                pointer_timestamp,
                start_arrival_perf_counter,
                start_at_epoch,
            ) = self._pending_start
            if pointer_record.get("anchor_id") == anchor_id:
                self._pending_start = None
                pointer_record["timestamp"] = pointer_timestamp
                anchor_perf_counter = (
                    self._observed_arp_anchor_perf_counters[anchor_id]
                )
                self._record_start_pointer(
                    pointer_record,
                    pointer_timestamp,
                    anchor_perf_counter,
                    max(start_arrival_perf_counter, anchor_perf_counter),
                    start_at_epoch=start_at_epoch,
                )
        return True

    def _parse_start_at_epoch(self, pointer_record):
        """Validate the shared start epoch carried by a startup pointer."""
        if self.counter_mode not in (SYNCED_CLOCK_MODE, *UTC_COUNTER_MODES):
            return None
        value = pointer_record.get("start_at_epoch")
        try:
            start_at_epoch = int(value)
        except (TypeError, ValueError):
            raise ValueError(
                "startup pointer has no valid start_at_epoch"
            ) from None
        if str(start_at_epoch) != str(value):
            raise ValueError("startup start_at_epoch must be an integer")
        if (
            self.counter_mode == SYNCED_CLOCK_MODE
            and start_at_epoch % 60 != 0
        ):
            raise ValueError(
                "synchronized start_at_epoch must be an integer minute boundary"
            )
        if (
            self.counter_mode in UTC_COUNTER_MODES
            and start_at_epoch <= utc_tick_epoch()
        ):
            raise ValueError(
                "UTC startup tick has already started; clocks may be out of sync"
            )
        return start_at_epoch

    def _parse_group_metadata(self, pointer_record):
        """Validate stable group/window indexes carried by option 4."""
        try:
            group_index = int(pointer_record["group_index"])
            group_attempt = int(pointer_record["group_attempt"])
            group_window_index = int(pointer_record["group_window_index"])
            group_window_count = int(pointer_record["group_window_count"])
            window_index = int(pointer_record["window_index"])
            message_bit_length = int(pointer_record["message_bit_length"])
            group_start_tick_epoch = int(
                pointer_record["group_start_tick_epoch"]
            )
        except (KeyError, TypeError, ValueError):
            raise ValueError("group pointer has missing or invalid indexes") from None

        values = (
            group_index,
            group_attempt,
            group_window_index,
            group_window_count,
            window_index,
            message_bit_length,
            group_start_tick_epoch,
        )
        if any(value < 0 for value in values) or group_attempt < 1:
            raise ValueError("group pointer indexes must be non-negative")
        if not pointer_record.get("sender_session_id"):
            raise ValueError("group pointer has no sender session id")
        if message_bit_length <= 0:
            raise ValueError("group pointer has invalid message length")
        if (
            self._utc_start_tick_epoch is None
            or group_start_tick_epoch < self._utc_start_tick_epoch
            or counter_for_utc_tick(
                group_start_tick_epoch,
                self._utc_start_tick_epoch,
            )
            != 0
        ):
            raise ValueError(
                "group start is not aligned to the original UTC counter 0000"
            )
        try:
            data_tick_epoch = int(pointer_record["tick_epoch"])
        except (KeyError, TypeError, ValueError):
            raise ValueError("group pointer has no valid UTC tick") from None
        if data_tick_epoch < group_start_tick_epoch:
            raise ValueError("group pointer predates its counter-0000 sync point")
        window_bits = pointer_record.get("window_bits")
        counter_bits = pointer_record.get("counter_bits")
        if (
            not isinstance(window_bits, str)
            or not 1 <= len(window_bits) <= OUTPUT_BITS
            or any(bit not in "01" for bit in window_bits)
            or not isinstance(counter_bits, str)
            or len(counter_bits) != OUTPUT_BITS
            or any(bit not in "01" for bit in counter_bits)
        ):
            raise ValueError("group pointer has invalid window bits")

        total_windows = (
            message_bit_length + OUTPUT_BITS - 1
        ) // OUTPUT_BITS
        group_start_window = group_index * GROUP_WINDOW_COUNT
        expected_count = min(
            GROUP_WINDOW_COUNT,
            max(0, total_windows - group_start_window),
        )
        if (
            not 1 <= group_window_count <= GROUP_WINDOW_COUNT
            or group_window_count != expected_count
            or group_window_index >= group_window_count
            or window_index != group_start_window + group_window_index
        ):
            raise ValueError("group pointer indexes do not match its message")
        expected_width = min(
            OUTPUT_BITS,
            message_bit_length - window_index * OUTPUT_BITS,
        )
        candidate = counter_bits[:expected_width]
        if len(window_bits) != expected_width or candidate != window_bits:
            raise ValueError("group pointer window bits do not match its counter")
        sync_key = (
            pointer_record["sender_session_id"],
            group_index,
            group_attempt,
        )
        announced_epoch = self._group_attempt_start_epochs.get(sync_key)
        if (
            announced_epoch is not None
            and announced_epoch != group_start_tick_epoch
        ):
            raise ValueError("group pointer UTC sync point changed during attempt")

        return {
            "sender_session_id": pointer_record["sender_session_id"],
            "group_index": group_index,
            "group_attempt": group_attempt,
            "group_window_index": group_window_index,
            "group_window_count": group_window_count,
            "window_index": window_index,
            "message_bit_length": message_bit_length,
            "window_bits": window_bits,
            "group_start_tick_epoch": group_start_tick_epoch,
        }

    def _record_group_start_marker(self, pointer_record, timestamp):
        """Record the common run-relative counter-0000 tick before replay."""
        try:
            sender_session_id = pointer_record["sender_session_id"]
            group_index = int(pointer_record["group_index"])
            group_attempt = int(pointer_record["group_attempt"])
            start_tick_epoch = int(pointer_record["group_start_tick_epoch"])
        except (KeyError, TypeError, ValueError):
            self._note_recognition_rejection(
                "group sync marker has missing or invalid metadata"
            )
            return
        if (
            not sender_session_id
            or group_index < 0
            or group_attempt < 1
            or self._utc_start_tick_epoch is None
            or start_tick_epoch < self._utc_start_tick_epoch
            or counter_for_utc_tick(
                start_tick_epoch,
                self._utc_start_tick_epoch,
            )
            != 0
        ):
            self._note_recognition_rejection(
                "group sync marker is not aligned to the original UTC counter 0000"
            )
            return

        if self._group_sender_session_id != sender_session_id:
            self._group_sender_session_id = sender_session_id
            self._final_group_complete = False
            self._group_attempt_start_epochs.clear()
        key = (sender_session_id, group_index, group_attempt)
        previous_epoch = self._group_attempt_start_epochs.get(key)
        if previous_epoch is not None and previous_epoch != start_tick_epoch:
            self._note_recognition_rejection(
                "group sync marker changed the UTC tick during an attempt"
            )
            return
        self._group_attempt_start_epochs[key] = start_tick_epoch
        self._last_pointer_sample_count = self.sample_count
        self._group_retry_pending = False
        self.store.append_event({
            "event_type": "group_attempt_sync",
            "session_id": self.session_id,
            "timestamp": timestamp,
            "sender_session_id": sender_session_id,
            "group_index": group_index,
            "group_attempt": group_attempt,
            "group_start_tick_epoch": start_tick_epoch,
            "counter_at_sync": 0,
        })
        print(
            f"Group {group_index + 1} attempt {group_attempt} aligned at "
            f"the same counter 0000 UTC tick {start_tick_epoch}.",
            flush=True,
        )

    def _record_pointer(self, pointer_record, timestamp, capture_epoch=None):
        """Match a pointer to the local counter for its UTC tick or latest sample."""
        pointer_record["timestamp"] = timestamp
        buffer_snapshot = self.store.newest_first
        empty_status = "buffer_empty"
        if self.counter_mode in UTC_COUNTER_MODES:
            if capture_epoch is None:
                capture_epoch = time.time()
            advertised_bits = pointer_record.get("counter_bits")
            if (
                not isinstance(advertised_bits, str)
                or len(advertised_bits) != OUTPUT_BITS
                or any(bit not in "01" for bit in advertised_bits)
            ):
                history_record = None
                empty_status = "missing_or_invalid_counter_bits"
            else:
                tick_value = pointer_record.get("tick_epoch")
                try:
                    tick_epoch = int(tick_value)
                except (TypeError, ValueError):
                    tick_epoch = None
                if (
                    tick_epoch is None
                    or str(tick_epoch) != str(tick_value)
                ):
                    history_record = None
                    empty_status = "missing_or_invalid_tick_epoch"
                elif (
                    self._utc_start_tick_epoch is None
                    or tick_epoch < self._utc_start_tick_epoch
                ):
                    history_record = None
                    empty_status = "tick_epoch_before_utc_run_start"
                else:
                    counter = counter_for_utc_tick(
                        tick_epoch,
                        self._utc_start_tick_epoch,
                    )
                    advertised_counter = int(advertised_bits, 2)
                    if counter != advertised_counter:
                        history_record = None
                        empty_status = "utc_counter_does_not_match_tick_epoch"
                    else:
                        history_record = {
                            "session_id": self.session_id,
                            "sample_no": tick_epoch,
                            "protocol": "PERIODIC",
                            "counter_mode": self.counter_mode,
                            "timestamp": timestamp,
                            "counter": counter,
                            "counter_bits": f"{counter:0{OUTPUT_BITS}b}",
                            "clock_tick_epoch": tick_epoch,
                        }
                        pointer_record["utc_tick_epoch"] = tick_epoch
                        pointer_record[
                            "utc_tick_arrival_offset_seconds"
                        ] = round(
                            capture_epoch
                            - (tick_epoch + UTC_TICK_PHASE_SECONDS),
                            3,
                        )
            if history_record is None:
                self._note_recognition_rejection(
                    f"UTC pointer sample could not be matched: {empty_status}"
                )
        else:
            history_record = self.store.latest

        group_metadata = None
        if self.counter_mode == GROUP_MODE:
            try:
                group_metadata = self._parse_group_metadata(pointer_record)
            except ValueError as exc:
                self._note_recognition_rejection(str(exc))
                return None

        pointer_event = self.secret_bits_store.record_pointer(
            pointer_record,
            history_record,
            buffer_snapshot=buffer_snapshot,
            empty_status=empty_status,
            group_metadata=group_metadata,
        )
        if group_metadata is not None:
            if (
                self._group_sender_session_id
                != group_metadata["sender_session_id"]
            ):
                self._group_sender_session_id = group_metadata[
                    "sender_session_id"
                ]
                self._final_group_complete = False
            total_windows = (
                group_metadata["message_bit_length"] + OUTPUT_BITS - 1
            ) // OUTPUT_BITS
            group_end_window = (
                group_metadata["group_index"] * GROUP_WINDOW_COUNT
                + group_metadata["group_window_count"]
            )
            if (
                pointer_event.get("group_complete")
                and group_end_window >= total_windows
            ):
                self._final_group_complete = True
        self.store.append_event({
            "event_type": "pointer",
            "session_id": self.session_id,
            "protocol": "mDNS",
            "timestamp": timestamp,
            **pointer_record,
            "buffer_before_pop": buffer_snapshot,
            "selected_record": history_record,
            "pointer_no": pointer_event["pointer_no"],
            "status": pointer_event["status"],
            "counter": pointer_event.get("counter"),
            "counter_bits": pointer_event.get("bits"),
        })
        if history_record is not None and self.counter_mode not in UTC_COUNTER_MODES:
            self.store.pop_latest()
        self._last_pointer_sample_count = self.sample_count
        self._group_retry_pending = False
        print(
            f"Pointer from "
            f"{pointer_record['src_ip'] or pointer_record['src_mac'] or '?'} "
            f"status={pointer_event['status']}; "
            f"bits={pointer_event.get('bits', '')}; "
            f"secret length="
            f"{self.secret_bits_store.data['bit_length']} bits.",
            flush=True,
        )
        return pointer_event

    def _note_recognition_rejection(self, reason):
        """Count rejected capture candidates and print each reason once."""
        count = self.recognition_rejections.get(reason, 0) + 1
        self.recognition_rejections[reason] = count
        if count == 1:
            print(f"Captured packet ignored: {reason}.", flush=True)

    def _send_group_ack(self, pointer_record):
        """Multicast one group-complete pointer back to the sender."""
        group_index = int(pointer_record["group_index"])
        group_attempt = int(pointer_record["group_attempt"])
        target_session_id = pointer_record["sender_session_id"]
        event_id = (
            f"r{self.session_id[:12]}-g{group_index + 1}-a{group_attempt}"
        )
        source_ip = get_if_addr(self.iface)
        source_mac = get_if_hwaddr(self.iface)
        fields = [
            POINTER_TXT_SIGNATURE,
            f"event_id={event_id}",
            f"counter_mode={GROUP_MODE}",
            "signal_type=group_ack",
            f"target_session_id={target_session_id}",
            f"group_index={group_index}",
            f"group_attempt={group_attempt}",
            f"group_window_count={pointer_record['group_window_count']}",
        ]
        answer = DNSRR(
            rrname=f"{event_id}._hcc-pointer._udp.local.",
            type="TXT",
            cacheflush=1,
            ttl=120,
            rdata=[field.encode("ascii") for field in fields],
        )
        packet = (
            Ether(src=source_mac, dst=MDNS_GROUP_MAC)
            / IP(src=source_ip, dst=MDNS_GROUP_IP, ttl=255)
            / UDP(sport=MDNS_PORT, dport=MDNS_PORT)
            / DNS(id=0, qr=1, aa=1, ancount=1, an=answer)
        )
        try:
            sendp(packet, iface=self.iface, count=1, verbose=False)
            send_status = "sent"
        except Exception as exc:
            send_status = "failed"
            print(f"Could not send group ACK for {event_id}: {exc}", flush=True)
        self.store.append_event({
            "event_type": "group_ack",
            "session_id": self.session_id,
            "timestamp": timestamp_now(),
            "event_id": event_id,
            "target_session_id": target_session_id,
            "group_index": group_index,
            "group_attempt": group_attempt,
            "group_window_count": int(pointer_record["group_window_count"]),
            "destination_ip": MDNS_GROUP_IP,
            "destination_port": MDNS_PORT,
            "send_status": send_status,
            "wire_frame_hex": bytes(packet).hex(),
        })
        print(
            f"Group {group_index + 1} complete; receiver group pointer "
            f"{send_status} for attempt {group_attempt}.",
            flush=True,
        )

    def _process_packet(
        self,
        packet,
        timestamp,
        arrival_perf_counter,
        capture_epoch=None,
    ):
        """Observe ARP anchors and process startup/data pointers in order."""
        self._emit_due_periodic_values(arrival_perf_counter, capture_epoch)
        if self._stop_requested.is_set():
            return
        if self._observe_arp_anchor(
            packet, timestamp, arrival_perf_counter
        ):
            return
        pointer_record, rejection = self.pointer_recognizer.inspect(packet)
        if pointer_record is None:
            self._note_recognition_rejection(rejection)
            return

        self.recognized_pointer_count += 1
        if pointer_record.get("counter_mode") != self.counter_mode:
            self._note_recognition_rejection(
                "pointer counter_mode is "
                f"{pointer_record.get('counter_mode')!r}; expected "
                f"{self.counter_mode!r}"
            )
            return

        signal_type = pointer_record.get("signal_type")
        if signal_type == "arm":
            self._record_arm_pointer(pointer_record, timestamp)
            return

        if signal_type == "start":
            if not self._start_pointer_seen:
                if not self._startup_armed:
                    self._note_recognition_rejection(
                        "startup confirmation arrived before the receiver was armed"
                    )
                    return
                anchor_id = pointer_record.get("anchor_id")
                if not anchor_id:
                    self._note_recognition_rejection(
                        "startup pointer has no ARP anchor id"
                    )
                    return
                try:
                    start_at_epoch = self._parse_start_at_epoch(pointer_record)
                except ValueError as exc:
                    self._note_recognition_rejection(str(exc))
                    return
                if anchor_id not in self._observed_arp_anchors:
                    self._pending_start = (
                        pointer_record,
                        timestamp,
                        arrival_perf_counter,
                        start_at_epoch,
                    )
                    print(
                        f"Startup pointer received; waiting to observe its "
                        f"ARP anchor {anchor_id}.",
                        flush=True,
                    )
                    return
                pointer_record["timestamp"] = timestamp
                self._record_start_pointer(
                    pointer_record,
                    timestamp,
                    self._observed_arp_anchor_perf_counters[anchor_id],
                    arrival_perf_counter,
                    start_at_epoch=start_at_epoch,
                )
            return
        if signal_type == "group_start":
            if self.counter_mode != GROUP_MODE:
                self._note_recognition_rejection(
                    "group sync marker is only valid in UTC group mode"
                )
                return
            if not self._start_pointer_seen:
                self._note_recognition_rejection(
                    "group sync marker arrived before the startup pointer"
                )
                return
            self._record_group_start_marker(pointer_record, timestamp)
            return
        if not self._start_pointer_seen:
            self._note_recognition_rejection(
                "valid data pointer arrived before the startup pointer"
            )
            return
        pointer_event = self._record_pointer(
            pointer_record, timestamp, capture_epoch
        )
        if (
            self.counter_mode == GROUP_MODE
            and pointer_event is not None
            and pointer_event.get("group_complete")
        ):
            self._send_group_ack(pointer_record)

    def _process_loop(self):
        """Proses frame antrean dan timer counter pada satu worker terurut."""
        while True:
            timeout = None
            if (
                self.counter_mode in UTC_COUNTER_MODES
                and self._next_utc_tick_epoch is not None
                and not self._stop_requested.is_set()
            ):
                timeout = max(
                    0.0,
                    self._next_utc_tick_epoch
                    + UTC_TICK_PHASE_SECONDS
                    - time.time(),
                )
            elif (
                self._next_periodic_tick is not None
                and not self._stop_requested.is_set()
            ):
                timeout = max(
                    0.0,
                    self._next_periodic_tick - time.perf_counter(),
                )
            try:
                item = self._queue.get(timeout=timeout)
            except queue.Empty:
                if not self._stop_requested.is_set():
                    self._emit_due_periodic_values(
                        time.perf_counter(), time.time()
                    )
                continue

            try:
                if item is None:
                    break
                packet, timestamp, arrival_perf_counter, capture_epoch = item
                try:
                    self._process_packet(
                        packet,
                        timestamp,
                        arrival_perf_counter,
                        capture_epoch,
                    )
                except Exception as exc:
                    print(f"Packet processing failed: {exc}", flush=True)
            finally:
                self._queue.task_done()

    def start(self):
        """Sniff ARP anchors and mDNS pointers until capture ends."""
        if self.iface is None:
            print("Sniffing on interface: Scapy default", flush=True)
        else:
            print(
                f"Sniffing on interface: {describe_interface(self.iface)}",
                flush=True,
            )
        if self.counter_mode in UTC_COUNTER_MODES:
            counter_schedule = (
                "counter derived from UTC seconds "
                f"(sample phase +{UTC_TICK_PHASE_SECONDS:g} seconds)"
            )
        else:
            counter_schedule = (
                "packet independent "
                f"(interval {PERIODIC_COUNTER_INTERVAL_SECONDS:g} seconds)"
            )
        print(
            f"Counter mode: {self.counter_mode}, {counter_schedule}.",
            flush=True,
        )
        if self.counter_mode == GROUP_MODE:
            print(
                "Group replay detection: "
                f"more than {GROUP_RETRY_TIMEOUT_SECONDS} seconds without "
                "a pointer.",
                flush=True,
            )
        else:
            print(
                "No-pointer stop threshold: "
                f"{POINTER_IDLE_COUNTER_SAMPLES} counter attempts.",
                flush=True,
            )
        print(f"Capture filter: {CAPTURE_FILTER}", flush=True)
        print(
            f"Pointer source IPv4: {self.pointer_recognizer.sender_ip}",
            flush=True,
        )
        if self.counter_mode == SYNCED_CLOCK_MODE:
            print(
                "Sniffing broadcast ARP directly; waiting for its matching "
                "startup confirmation.",
                flush=True,
            )
            print(
                "Synchronized clock mode assumes both system clocks were "
                "synchronized before communication; sampling starts at the "
                "next minute boundary after ARP. Start the receiver before "
                "the sender so it can capture the ARP anchor.",
                flush=True,
            )
        elif self.counter_mode in UTC_COUNTER_MODES:
            print(
                "Waiting for startup mDNS arm, then an ARP anchor and matching "
                "confirmation. UTC counter values follow each shared UTC "
                "second; keep both system clocks synchronized.",
                flush=True,
            )
            if self.counter_mode == GROUP_MODE:
                print(
                    "Option 4 stores each received window by its group/window "
                    "index. It sends a multicast group ACK after all windows "
                    "arrive; missing windows remain available for replay. "
                    f"After more than {GROUP_RETRY_TIMEOUT_SECONDS} seconds "
                    "without a pointer, it retains the group and waits for "
                    "replay.",
                    flush=True,
                )
        else:
            print(
                "Waiting for startup mDNS arm, then a broadcast ARP anchor and "
                "its matching confirmation before starting the counter.",
                flush=True,
            )
        print(
            "Extracting counter values; keeping the latest "
            f"{self.store.capacity} in the receiver buffer.",
            flush=True,
        )
        print("Press Ctrl+C to stop sniffing.\n", flush=True)

        self._worker = threading.Thread(target=self._process_loop, daemon=True)
        self._worker.start()
        started = threading.Event()
        sniffer = AsyncSniffer(
            iface=self.iface,
            filter=CAPTURE_FILTER,
            prn=self._on_sniff_packet,
            store=False,
            started_callback=started.set,
        )
        sniffer_started = False
        try:
            sniffer.start()
            sniffer_started = True
            if not started.wait(timeout=5):
                raise RuntimeError("Scapy sniffer did not start within 5 seconds.")
            while sniffer.running and not self._stop_requested.wait(0.1):
                pass
        finally:
            try:
                if sniffer_started:
                    if sniffer.running:
                        sniffer.stop()
                    else:
                        sniffer.join()
            finally:
                self._queue.put(None)
                self._queue.join()
                self._worker.join()

            print(
                f"Capture received {self.captured_packet_count} frame(s); "
                f"{self.sample_count} produced counter values.",
                flush=True,
            )
            print(
                f"Pointer recognition: {self.recognized_pointer_count} valid "
                f"pointer frame(s); {sum(self.recognition_rejections.values())} "
                "rejected candidate(s).",
                flush=True,
            )
            for reason, count in self.recognition_rejections.items():
                print(f"  {count} frame(s): {reason}", flush=True)
            print(f"Latest buffer: {self.store.buffer_path}", flush=True)
            print(f"Append-only log: {self.store.log_path}", flush=True)
            print(f"Secret bits: {self.secret_bits_store.filepath}", flush=True)
