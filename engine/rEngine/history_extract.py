"""Tangkap pointer Periodic-B dan hubungkan counter dengan receiver.

Filter hanya mengambil mDNS pointer. Counter history bits berjalan berdasarkan
timer lokal dan tidak memakai PoI.
"""

import json
import queue
import threading
import time
import uuid
from datetime import datetime

from scapy.sendrecv import AsyncSniffer

from engine.interface_utils import describe_interface
from engine.periodic_counter import (
    OUTPUT_BITS,
    PERIODIC_MODE,
    PERIODIC_COUNTER_INTERVAL_SECONDS,
    PeriodicCounterState,
    timestamp_now,
)
from engine.pointer_protocol import MDNS_GROUP_IP, MDNS_PORT
from .history_buffer import ReceiverHistoryStore
from .pointer_recognition import PointerRecognizer
from .secret_bits import ReceiverSecretBitsStore


# Receiver hanya menangkap pointer; counter dibuat lokal per interval.
POINTER_FILTER = (
    f"(udp and dst port {MDNS_PORT} and dst host {MDNS_GROUP_IP})"
)
CAPTURE_FILTER = POINTER_FILTER


class ReceiverHistoryExtractor:
    """Kelola start-pointer, sampling periodik, dan pointer data."""

    def __init__(
        self,
        iface,
        buffer_path,
        log_path,
        secret_bits_path,
        pointer_source_ip,
    ):
        """Hubungkan recognizer, buffer, dan penyimpan secret untuk satu interface."""
        self.iface = iface
        self.counter_mode = PERIODIC_MODE
        self.store = ReceiverHistoryStore(
            buffer_path,
            log_path,
        )
        self.secret_bits_store = ReceiverSecretBitsStore(secret_bits_path)
        self.pointer_recognizer = PointerRecognizer(pointer_source_ip)
        self.session_id = uuid.uuid4().hex
        self.sample_count = 0
        self.captured_packet_count = 0
        self._counter_state = PeriodicCounterState()
        self._next_periodic_tick = None
        self._start_pointer_seen = False
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

    def _record_periodic_value(self):
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
            self._record_periodic_value()
            self._next_periodic_tick = max(
                next_tick,
                time.perf_counter() + PERIODIC_COUNTER_INTERVAL_SECONDS,
            )

    def _record_start_pointer(
        self, pointer_record, timestamp, arrival_perf_counter
    ):
        """Start the local timer when the sender's startup pointer arrives."""
        self._start_pointer_seen = True
        self._next_periodic_tick = arrival_perf_counter
        self.store.append_event({
            "event_type": "periodic_b_start_pointer",
            "session_id": self.session_id,
            "protocol": "mDNS",
            "counter_mode": self.counter_mode,
            "timestamp": timestamp,
            **pointer_record,
        })
        print(
            "Periodic-B startup pointer received; periodic counter started.",
            flush=True,
        )
        self._emit_due_periodic_values(arrival_perf_counter)

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

    def _process_packet(self, packet, timestamp, arrival_perf_counter):
        """Start from a control pointer and process later data pointers."""
        self._emit_due_periodic_values(arrival_perf_counter)
        pointer_record = self.pointer_recognizer.recognize(packet)
        if pointer_record is not None:
            is_start_pointer = (
                pointer_record.get("signal_type") == "start"
                and pointer_record.get("counter_mode") == PERIODIC_MODE
            )
            if is_start_pointer:
                if not self._start_pointer_seen:
                    pointer_record["timestamp"] = timestamp
                    self._record_start_pointer(
                        pointer_record,
                        timestamp,
                        arrival_perf_counter,
                    )
                return
            if not self._start_pointer_seen:
                return
            self._record_pointer(pointer_record, timestamp)
            return

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
        """Sniff mDNS pointers and stop the worker cleanly when capture ends."""
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
            print(f"Latest buffer: {self.store.buffer_path}", flush=True)
            print(f"Append-only log: {self.store.log_path}", flush=True)
            print(f"Secret bits: {self.secret_bits_store.filepath}", flush=True)
