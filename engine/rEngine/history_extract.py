"""Tangkap anchor ARP dan pointer Periodic-B untuk menghubungkan counter."""

import json
import queue
import threading
import time
import uuid
from collections import OrderedDict
from datetime import datetime

from scapy.sendrecv import AsyncSniffer

from engine.arp_anchor import ARP_ANCHOR_FILTER, get_arp_anchor
from engine.interface_utils import describe_interface
from engine.periodic_counter import (
    OUTPUT_BITS,
    PERIODIC_COUNTER_INTERVAL_SECONDS,
    PERIODIC_MODE,
    SYNCED_CLOCK_MODE,
    PeriodicCounterState,
    timestamp_now,
)
from engine.pointer_protocol import MDNS_GROUP_IP, MDNS_PORT
from .history_buffer import ReceiverHistoryStore
from .pointer_recognition import PointerRecognizer
from .secret_bits import ReceiverSecretBitsStore


# Receiver menangkap anchor ARP dan pointer; counter dibuat lokal per interval.
POINTER_FILTER = (
    f"(udp and dst port {MDNS_PORT} and dst host {MDNS_GROUP_IP})"
)
CAPTURE_FILTER = f"({ARP_ANCHOR_FILTER} or {POINTER_FILTER})"


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
        if counter_mode not in (PERIODIC_MODE, SYNCED_CLOCK_MODE):
            raise ValueError(
                "Receiver supports legacy or synchronized clock mode"
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
        self._startup_armed = False
        self._start_pointer_seen = False
        self._pending_start = None
        self._observed_arp_anchors = OrderedDict()
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
            wallclock = datetime.now().isoformat(timespec="milliseconds")
        self._queue.put((packet, wallclock, arrival_perf_counter))

    def _record_periodic_value(self, clock_tick_epoch=None):
        """Buat satu nilai counter, simpan ke buffer, dan tulis ke log receiver."""
        self.sample_count += 1
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

    def _emit_due_periodic_values(self, now_perf_counter):
        """Keluarkan sampel yang jadwal intervalnya sudah tiba."""
        while (
            self._next_periodic_tick is not None
            and now_perf_counter >= self._next_periodic_tick
        ):
            next_tick = self._next_periodic_tick + PERIODIC_COUNTER_INTERVAL_SECONDS
            tick_epoch = self._next_periodic_tick_epoch
            self._record_periodic_value(clock_tick_epoch=tick_epoch)
            self._next_periodic_tick = next_tick
            if tick_epoch is not None:
                self._next_periodic_tick_epoch = tick_epoch + int(
                    PERIODIC_COUNTER_INTERVAL_SECONDS
                )

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
        if start_at_epoch is None:
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
        self._emit_due_periodic_values(now_perf_counter)

    def _record_arm_pointer(self, pointer_record, timestamp):
        """Arm the receiver so only later ARP frames can anchor this run."""
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
        """Validate the shared minute boundary carried by a synced start pointer."""
        if self.counter_mode != SYNCED_CLOCK_MODE:
            return None
        value = pointer_record.get("start_at_epoch")
        try:
            start_at_epoch = int(value)
        except (TypeError, ValueError):
            raise ValueError(
                "synchronized startup pointer has no valid start_at_epoch"
            ) from None
        if str(start_at_epoch) != str(value) or start_at_epoch % 60 != 0:
            raise ValueError(
                "synchronized start_at_epoch must be an integer minute boundary"
            )
        return start_at_epoch

    def _record_pointer(self, pointer_record, timestamp):
        """Pasangkan pointer data dengan counter terbaru, lalu tambah bit ke secret."""
        pointer_record["timestamp"] = timestamp
        buffer_snapshot = self.store.newest_first
        history_record = self.store.latest
        pointer_event = self.secret_bits_store.record_pointer(
            pointer_record,
            history_record,
            buffer_snapshot=buffer_snapshot,
        )
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
        if history_record is not None:
            self.store.pop_latest()
        print(
            f"Pointer from "
            f"{pointer_record['src_ip'] or pointer_record['src_mac'] or '?'} "
            f"status={pointer_event['status']}; "
            f"bits={pointer_event.get('bits', '')}; "
            f"secret length="
            f"{self.secret_bits_store.data['bit_length']} bits.",
            flush=True,
        )

    def _note_recognition_rejection(self, reason):
        """Count rejected capture candidates and print each reason once."""
        count = self.recognition_rejections.get(reason, 0) + 1
        self.recognition_rejections[reason] = count
        if count == 1:
            print(f"Captured packet ignored: {reason}.", flush=True)

    def _process_packet(self, packet, timestamp, arrival_perf_counter):
        """Observe ARP anchors and process startup/data pointers in order."""
        self._emit_due_periodic_values(arrival_perf_counter)
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

        if pointer_record.get("signal_type") == "arm":
            self._record_arm_pointer(pointer_record, timestamp)
            return

        if pointer_record.get("signal_type") == "start":
            if not self._start_pointer_seen:
                if not self._startup_armed:
                    self._note_recognition_rejection(
                        "startup confirmation arrived before mDNS arm"
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
        if not self._start_pointer_seen:
            self._note_recognition_rejection(
                "valid data pointer arrived before the startup pointer"
            )
            return
        self._record_pointer(pointer_record, timestamp)

    def _process_loop(self):
        """Proses frame antrean dan timer counter pada satu worker terurut."""
        while True:
            timeout = None
            if self._next_periodic_tick is not None:
                timeout = max(
                    0.0,
                    self._next_periodic_tick - time.perf_counter(),
                )
            try:
                item = self._queue.get(timeout=timeout)
            except queue.Empty:
                self._emit_due_periodic_values(time.perf_counter())
                continue

            try:
                if item is None:
                    break
                packet, timestamp, arrival_perf_counter = item
                try:
                    self._process_packet(
                        packet,
                        timestamp,
                        arrival_perf_counter,
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
        print(
            f"Counter mode: {self.counter_mode}, packet independent "
            f"(interval {PERIODIC_COUNTER_INTERVAL_SECONDS:g} seconds).",
            flush=True,
        )
        print(f"Capture filter: {CAPTURE_FILTER}", flush=True)
        print(
            f"Pointer source IPv4: {self.pointer_recognizer.sender_ip}",
            flush=True,
        )
        print(
            "Waiting for startup mDNS arm, then a broadcast ARP anchor and "
            "its matching confirmation before starting the counter.",
            flush=True,
        )
        if self.counter_mode == SYNCED_CLOCK_MODE:
            print(
                "Synchronized clock mode assumes both system clocks were "
                "synchronized before communication; sampling starts at the "
                "next minute boundary after ARP.",
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
            while sniffer.running:
                time.sleep(0.1)
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
