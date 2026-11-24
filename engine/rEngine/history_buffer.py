"""Simpan rolling buffer periodic counter dan log event append-only receiver.

``ReceiverHistoryExtractor`` menambah counter ke sini, lalu mengambil sampel
terbaru untuk ``ReceiverSecretBitsStore`` saat pointer data diterima.
"""

import json
import os
from collections import deque
from pathlib import Path

from engine.periodic_counter import (
    OUTPUT_BITS,
    PERIODIC_MODE,
    SYNCED_CLOCK_MODE,
)


BUFFER_CAPACITY = 4


class ReceiverHistoryStore:
    """Kelola empat counter terbaru yang dikonsumsi pointer serta log historis."""

    def __init__(
        self,
        buffer_path,
        log_path,
        capacity=BUFFER_CAPACITY,
        counter_mode=PERIODIC_MODE,
    ):
        """Pulihkan buffer periodic yang tersimpan atau siapkan buffer baru."""
        if counter_mode not in (PERIODIC_MODE, SYNCED_CLOCK_MODE):
            raise ValueError(f"unsupported counter mode: {counter_mode!r}")
        self.buffer_path = Path(buffer_path)
        self.log_path = Path(log_path)
        self.capacity = capacity
        self.counter_mode = counter_mode
        self.buffer_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        existing, needs_rewrite = self._load_existing()
        self._buffer = deque(existing[:capacity], maxlen=capacity)
        if needs_rewrite:
            self._save_buffer()

    def _load_existing(self):
        """Validasi dan normalisasi buffer di disk sebelum dipakai kembali."""
        if not self.buffer_path.exists():
            return [], False

        with self.buffer_path.open("r", encoding="utf-8") as handle:
            saved = json.load(handle)
        if saved.get("counter_mode") != self.counter_mode:
            return [], True
        records = saved.get("counters")
        needs_rewrite = records is None
        if needs_rewrite:
            records = saved.get("history_bits", [])
        if not isinstance(records, list):
            raise ValueError(
                f"Invalid receiver history buffer format: {self.buffer_path}"
            )

        clean_records = []
        for record in records:
            if not isinstance(record, dict) or "counter" not in record:
                continue
            if record.get("counter_mode") != self.counter_mode:
                needs_rewrite = True
                continue
            counter_bits = record.get("counter_bits", record.get("history_bits"))
            if (
                not isinstance(counter_bits, str)
                or len(counter_bits) != OUTPUT_BITS
                or any(bit not in "01" for bit in counter_bits)
            ):
                continue
            clean_record = {
                "session_id": record.get("session_id"),
                "sample_no": record.get("sample_no"),
                "protocol": record.get("protocol"),
                "counter_mode": self.counter_mode,
                "timestamp": record.get("timestamp"),
                "counter": record["counter"],
                "counter_bits": counter_bits,
            }
            clock_tick_epoch = record.get("clock_tick_epoch")
            if (
                isinstance(clock_tick_epoch, int)
                and not isinstance(clock_tick_epoch, bool)
            ):
                clean_record["clock_tick_epoch"] = clock_tick_epoch
            clean_records.append(clean_record)
        return clean_records, needs_rewrite

    @property
    def newest_first(self):
        return list(self._buffer)

    @property
    def latest(self):
        return self._buffer[0] if self._buffer else None

    def _save_buffer(self):
        """Simpan snapshot buffer secara atomik agar file tidak tertinggal separuh."""
        output = {
            "counter_mode": self.counter_mode,
            "capacity": self.capacity,
            "order": "newest_first",
            "buffered_count": len(self._buffer),
            "counters": self.newest_first,
        }
        temporary_path = self.buffer_path.with_name(
            self.buffer_path.name + f".{os.getpid()}.tmp"
        )
        with temporary_path.open("w", encoding="utf-8") as handle:
            json.dump(output, handle, indent=2, ensure_ascii=False)
        os.replace(temporary_path, self.buffer_path)

    def _append_log(self, record):
        """Tulis satu record JSONL, dipakai counter dan event pointer."""
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    def add(self, record):
        """Catat counter dan geser buffer agar tetap berisi sampel paling baru."""
        self._append_log(record)
        self._buffer.appendleft(record)
        self._save_buffer()

    def append_event(self, record):
        """Catat event sinkronisasi atau pointer tanpa mengubah isi buffer counter."""
        self._append_log(record)

    def pop_latest(self):
        """Konsumsi counter terbaru setelah pointer diproses dan simpan ulang buffer."""
        if not self._buffer:
            return None
        record = self._buffer.popleft()
        self._save_buffer()
        return record
