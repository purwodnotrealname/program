"""Gabungkan counter yang dikonsumsi pointer menjadi secret bit receiver."""

import json
import os
from pathlib import Path

from engine.periodic_counter import OUTPUT_BITS


class ReceiverSecretBitsStore:
    """Simpan event pointer dan akumulasi bit tanpa menambahkan counter dua kali."""

    def __init__(self, filepath):
        """Pulihkan secret bits tersimpan atau buat struktur awal baru."""
        self.filepath = Path(filepath)
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        if self.filepath.exists():
            with self.filepath.open("r", encoding="utf-8") as handle:
                self.data = json.load(handle)
        else:
            self.data = {
                "secret_bits": "",
                "bit_length": 0,
                "chunks": [],
                "pointer_events": [],
            }
            self._save()
            return

        if "pointer_events" not in self.data:
            self.data["pointer_events"] = []
            self._save()

    def record_pointer(
        self,
        pointer_record,
        history_record,
        buffer_snapshot=None,
        empty_status="buffer_empty",
    ):
        """Hubungkan pointer ke counter terbaru dan tambahkan bit unik ke secret.

        Dipanggil oleh ``ReceiverHistoryExtractor`` setelah start-pointer dan ARP
        anchor memastikan run sudah tersinkronisasi.
        """
        existing_ids = {
            chunk.get("history_record_id") for chunk in self.data["chunks"]
        }
        pointer_event = {
            "pointer_no": len(self.data["pointer_events"]) + 1,
            "pointer": pointer_record,
            "buffer_snapshot": list(buffer_snapshot or []),
            "status": empty_status,
        }

        if history_record is not None:
            bits = history_record["counter_bits"]
            if len(bits) != OUTPUT_BITS or any(bit not in "01" for bit in bits):
                raise ValueError(
                    f"Counter record does not contain {OUTPUT_BITS} valid bits"
                )

            record_no = history_record.get("sample_no", "unknown")
            history_record_id = (
                f"{history_record.get('session_id', 'unknown')}:{record_no}"
            )
            if history_record_id in existing_ids:
                pointer_event["status"] = "counter_already_added"
                pointer_event["counter"] = history_record["counter"]
                pointer_event["bits"] = bits
            else:
                chunk = {
                    "chunk_no": len(self.data["chunks"]) + 1,
                    "history_record_id": history_record_id,
                    "counter": history_record["counter"],
                    "bits": bits,
                    "pointer_no": pointer_event["pointer_no"],
                }
                self.data["secret_bits"] += bits
                self.data["bit_length"] = len(self.data["secret_bits"])
                self.data["chunks"].append(chunk)
                pointer_event["status"] = "counter_added"
                pointer_event["counter"] = history_record["counter"]
                pointer_event["bits"] = bits

        self.data["pointer_events"].append(pointer_event)
        self._save()
        return pointer_event

    def _save(self):
        """Persist data secret secara atomik supaya JSON tetap utuh saat dihentikan."""
        temporary_path = self.filepath.with_name(
            self.filepath.name + f".{os.getpid()}.tmp"
        )
        with temporary_path.open("w", encoding="utf-8") as handle:
            json.dump(self.data, handle, indent=2, ensure_ascii=False)
        os.replace(temporary_path, self.filepath)
