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
        self.data.setdefault("chunks", [])

    def group_progress(
        self, sender_session_id, group_index, expected_window_count
    ):
        """Return which stable windows have arrived for one sender group."""
        run = next(
            (
                item for item in self.data.get("group_runs", [])
                if item.get("sender_session_id") == sender_session_id
            ),
            None,
        )
        group = None
        if run is not None:
            group = next(
                (
                    item for item in run.get("groups", [])
                    if item.get("group_index") == group_index
                ),
                None,
            )
        windows = group.get("windows", {}) if group is not None else {}
        received = [
            index for index in range(expected_window_count)
            if str(index) in windows
        ]
        missing = [
            index for index in range(expected_window_count)
            if str(index) not in windows
        ]
        return {
            "received_window_count": len(received),
            "missing_window_indices": missing,
            "complete": not missing,
        }

    def record_pointer(
        self,
        pointer_record,
        history_record,
        buffer_snapshot=None,
        empty_status="buffer_empty",
        group_metadata=None,
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

        if group_metadata is not None:
            return self._record_group_pointer(
                pointer_event,
                history_record,
                group_metadata,
            )

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

    def _record_group_pointer(
        self, pointer_event, history_record, group_metadata
    ):
        """Store grouped bits by stable window index so retries fill gaps."""
        sender_session_id = group_metadata["sender_session_id"]
        group_index = group_metadata["group_index"]
        local_window_index = group_metadata["group_window_index"]
        group_window_count = group_metadata["group_window_count"]
        group_runs = self.data.setdefault("group_runs", [])

        run = next(
            (
                item for item in group_runs
                if item.get("sender_session_id") == sender_session_id
            ),
            None,
        )
        if run is None:
            run = {
                "sender_session_id": sender_session_id,
                "message_bit_length": group_metadata["message_bit_length"],
                "groups": [],
            }
            group_runs.append(run)

        group = next(
            (
                item for item in run["groups"]
                if item.get("group_index") == group_index
            ),
            None,
        )
        if group is None:
            group = {
                "group_index": group_index,
                "group_window_count": group_window_count,
                "windows": {},
                "ack_attempts": [],
                "attempt_start_epochs": {},
            }
            run["groups"].append(group)
        elif group.get("group_window_count") != group_window_count:
            raise ValueError("group window count changed during replay")

        attempt_key = str(group_metadata["group_attempt"])
        prior_start_epoch = group.setdefault(
            "attempt_start_epochs", {}
        ).get(attempt_key)
        if (
            prior_start_epoch is not None
            and prior_start_epoch != group_metadata["group_start_tick_epoch"]
        ):
            raise ValueError("group replay changed its counter-0000 UTC anchor")
        group["attempt_start_epochs"][attempt_key] = group_metadata[
            "group_start_tick_epoch"
        ]

        window_key = str(local_window_index)
        group_complete_before = all(
            str(index) in group["windows"]
            for index in range(group_window_count)
        )
        if history_record is not None:
            bits = group_metadata["window_bits"]
            if (
                not 1 <= len(bits) <= OUTPUT_BITS
                or any(bit not in "01" for bit in bits)
            ):
                raise ValueError(
                    "Group window does not contain valid message bits"
                )
            existing = group["windows"].get(window_key)
            if existing is None:
                group["windows"][window_key] = {
                    "window_index": group_metadata["window_index"],
                    "bits": bits,
                    "counter": history_record["counter"],
                    "group_attempt": group_metadata["group_attempt"],
                    "pointer_no": pointer_event["pointer_no"],
                }
                pointer_event["status"] = "group_window_added"
                self._upsert_group_chunk(
                    sender_session_id,
                    group_index,
                    local_window_index,
                    group_metadata["window_index"],
                    history_record,
                    pointer_event["pointer_no"],
                    bits,
                )
            elif existing.get("bits") == bits:
                pointer_event["status"] = "group_window_already_recorded"
            else:
                existing.update({
                    "bits": bits,
                    "counter": history_record["counter"],
                    "group_attempt": group_metadata["group_attempt"],
                    "pointer_no": pointer_event["pointer_no"],
                })
                pointer_event["status"] = "group_window_replaced"
                self._upsert_group_chunk(
                    sender_session_id,
                    group_index,
                    local_window_index,
                    group_metadata["window_index"],
                    history_record,
                    pointer_event["pointer_no"],
                    bits,
                )

        missing_windows = [
            index for index in range(group_window_count)
            if str(index) not in group["windows"]
        ]
        group_complete = not missing_windows
        pointer_event["group"] = {
            **group_metadata,
            "group_complete": group_complete,
            "missing_window_indices": missing_windows,
        }
        if group_complete:
            if group_metadata["group_attempt"] not in group["ack_attempts"]:
                group["ack_attempts"].append(group_metadata["group_attempt"])
        pointer_event["group_complete_before_pointer"] = group_complete_before
        pointer_event["group_complete"] = group_complete
        pointer_event["missing_window_indices"] = missing_windows

        if history_record is not None:
            pointer_event["counter"] = history_record["counter"]
            pointer_event["bits"] = group_metadata["window_bits"]
        self._rebuild_grouped_secret_bits()
        self.data["pointer_events"].append(pointer_event)
        self._save()
        return pointer_event

    def _upsert_group_chunk(
        self,
        sender_session_id,
        group_index,
        local_window_index,
        window_index,
        history_record,
        pointer_no,
        bits,
    ):
        chunk_id = (
            f"group:{sender_session_id}:{group_index}:{local_window_index}"
        )
        chunk = next(
            (
                item for item in self.data["chunks"]
                if item.get("history_record_id") == chunk_id
            ),
            None,
        )
        if chunk is None:
            chunk = {
                "chunk_no": len(self.data["chunks"]) + 1,
                "history_record_id": chunk_id,
            }
            self.data["chunks"].append(chunk)
        chunk.update({
            "group_index": group_index,
            "window_index": window_index,
            "counter": history_record["counter"],
            "bits": bits,
            "pointer_no": pointer_no,
        })

    def _rebuild_grouped_secret_bits(self):
        """Build only the contiguous prefix; indexed groups retain any gaps."""
        if "legacy_secret_bits" not in self.data:
            self.data["legacy_secret_bits"] = self.data.get("secret_bits", "")
        parts = [self.data["legacy_secret_bits"]]
        for run in self.data.get("group_runs", []):
            for group in sorted(
                run.get("groups", []), key=lambda item: item["group_index"]
            ):
                windows = group.get("windows", {})
                for index in range(group["group_window_count"]):
                    window = windows.get(str(index))
                    if window is None:
                        return self._set_secret_bits("".join(parts))
                    parts.append(window["bits"])
        self._set_secret_bits("".join(parts))

    def _set_secret_bits(self, bits):
        self.data["secret_bits"] = bits
        self.data["bit_length"] = len(bits)

    def _save(self):
        """Persist data secret secara atomik supaya JSON tetap utuh saat dihentikan."""
        temporary_path = self.filepath.with_name(
            self.filepath.name + f".{os.getpid()}.tmp"
        )
        with temporary_path.open("w", encoding="utf-8") as handle:
            json.dump(self.data, handle, indent=2, ensure_ascii=False)
        os.replace(temporary_path, self.filepath)
