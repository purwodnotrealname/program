"""Generate sender history bits from a packet-independent periodic counter."""

import json
import time

from scapy.all import conf, get_if_list

from engine.periodic_counter import (
    GROUP_MODE,
    GROUP_WINDOW_COUNT,
    OUTPUT_BITS,
    PERIODIC_COUNTER_INTERVAL_SECONDS,
    PERIODIC_MODE,
    SYNCED_CLOCK_MODE,
    UTC_COUNTER_MODES,
    UTC_MAX_SAMPLE_PHASE_SECONDS,
    UTC_TICK_PHASE_SECONDS,
    PeriodicCounterState,
    counter_for_utc_tick,
    is_utc_minute_anchor_epoch,
    timestamp_now,
    utc_tick_epoch,
)


class ICDExtractor:
    """Run Periodic-B counter samples and match them against message windows."""

    def __init__(
        self,
        iface=None,
        matcher=None,
        on_match=None,
        on_start=None,
        on_group_start=None,
        on_group_response=None,
        counter_mode=PERIODIC_MODE,
        on_group_response_pending=None,
    ):
        if counter_mode not in (
            PERIODIC_MODE,
            SYNCED_CLOCK_MODE,
            *UTC_COUNTER_MODES,
        ):
            raise ValueError(
                "ICDExtractor supports legacy, synchronized clock, UTC, "
                "or UTC group mode"
            )
        if not callable(on_start):
            raise ValueError("Periodic-B requires an on_start pointer callback")
        if counter_mode == GROUP_MODE and not all(
            callable(callback)
            for callback in (
                on_match,
                on_group_start,
                on_group_response,
                on_group_response_pending,
            )
        ):
            raise ValueError(
                "UTC group mode requires pointer and response callbacks"
            )

        self.iface = iface
        self.counter_mode = counter_mode
        self.matcher = matcher
        self.on_match = on_match
        self.on_start = on_start
        self.on_group_start = on_group_start
        self.on_group_response = on_group_response
        self.on_group_response_pending = on_group_response_pending
        self.records = []
        self.sample_count = 0
        self.t0_wallclock = None
        self._counter_state = PeriodicCounterState()
        self._utc_start_tick_epoch = None

    def _process_periodic_sample(
        self, sample_no, clock_tick_epoch=None, group_info=None
    ):
        if self.counter_mode in UTC_COUNTER_MODES and clock_tick_epoch is not None:
            if self._utc_start_tick_epoch is None:
                raise RuntimeError("UTC start tick has not been initialized")
            counter_anchor_epoch = self._utc_start_tick_epoch
            if self.counter_mode == GROUP_MODE and group_info is not None:
                counter_anchor_epoch = group_info["group_start_tick_epoch"]
            counter = counter_for_utc_tick(
                clock_tick_epoch,
                counter_anchor_epoch,
            )
        else:
            counter = self._counter_state.next_value()
        record = {
            "sample_no": sample_no,
            "protocol": "PERIODIC",
            "counter_mode": self.counter_mode,
            "timestamp": timestamp_now(),
            "counter": counter,
            "bit_value": counter,
        }
        if clock_tick_epoch is not None:
            record["clock_tick_epoch"] = clock_tick_epoch
        self.records.append(record)
        self.sample_count += 1

        attempt = None
        match_result = None
        if self.matcher is not None and not self.matcher.is_complete:
            attempt = self.matcher.try_match(
                bit_value=counter,
                sample_no=sample_no,
            )
            attempt["counter_mode"] = self.counter_mode
            if group_info is not None:
                attempt.update(group_info)

        print(
            f"[{sample_no:04d}] PERIODIC counter={counter:02d} "
            f"- bits={counter:0{OUTPUT_BITS}b}",
            flush=True,
        )

        if attempt is not None:
            window_display = (
                f"{attempt['window_value']:0{attempt['window_width']}b}"
            )
            compared_display = (
                f"{attempt['compared_value']:0{attempt['window_width']}b}"
            )
            print(
                f"       - window {attempt['window_index']:02d} "
                f"[{window_display}] vs [{compared_display}] "
                f"= {attempt['status'].upper()}",
                flush=True,
            )
            if attempt["status"] == "matched" and self.on_match is not None:
                try:
                    match_result = self.on_match(
                        {**attempt, "sample": record}
                    )
                except Exception as exc:
                    print(f"       - pointer signal failed: {exc}", flush=True)
        return match_result

    def _start_grouped_utc(self, start_reference):
        """Run sequential groups and wait for receiver-directed replay/advance."""
        if isinstance(start_reference, bool) or not isinstance(
            start_reference, int
        ) or not is_utc_minute_anchor_epoch(start_reference):
            raise ValueError(
                "UTC group mode requires the shared next-second-00 anchor"
            )
        if self.matcher is None:
            raise ValueError("UTC group mode requires a message matcher")

        self._utc_start_tick_epoch = start_reference
        total_windows = len(self.matcher.windows)
        total_groups = (
            total_windows + GROUP_WINDOW_COUNT - 1
        ) // GROUP_WINDOW_COUNT
        group_start = 0
        group_attempt = 1
        next_tick_epoch = start_reference

        while group_start < total_windows:
            group_end = min(group_start + GROUP_WINDOW_COUNT, total_windows)
            group_window_count = group_end - group_start
            self.matcher.reset_to(group_start)
            group_bit_start = group_start * self.matcher.window_size
            group_bit_end = min(
                self.matcher.bit_length,
                group_end * self.matcher.window_size,
            )
            print(
                f"Group {group_start // GROUP_WINDOW_COUNT + 1}/"
                f"{total_groups}: bits {group_bit_start + 1}-{group_bit_end} "
                f"({group_bit_end - group_bit_start} bits), "
                f"attempt {group_attempt}.",
                flush=True,
            )
            self.on_group_start(
                group_start // GROUP_WINDOW_COUNT,
                group_attempt,
            )

            group_index = group_start // GROUP_WINDOW_COUNT
            group_start_tick_epoch = next_tick_epoch
            group_response = None
            while self.matcher.pointer < group_end:
                if self.on_group_response_pending(
                    group_index,
                    group_attempt,
                ):
                    group_response = self.on_group_response(
                        group_index,
                        group_attempt,
                        group_window_count,
                        self.matcher.bit_length,
                    )
                    break
                delay = (
                    next_tick_epoch + UTC_TICK_PHASE_SECONDS - time.time()
                )
                if delay > 0:
                    time.sleep(delay)

                # A receiver control may arrive while the sender sleeps for
                # this tick. Honor it before sampling or advancing the matcher.
                if self.on_group_response_pending(
                    group_index,
                    group_attempt,
                ):
                    group_response = self.on_group_response(
                        group_index,
                        group_attempt,
                        group_window_count,
                        self.matcher.bit_length,
                    )
                    break

                now_epoch = time.time()
                due_tick_epoch = utc_tick_epoch(now_epoch)
                if due_tick_epoch < next_tick_epoch:
                    continue
                if due_tick_epoch > next_tick_epoch:
                    print(
                        f"Skipped {due_tick_epoch - next_tick_epoch} late "
                        "UTC counter tick(s).",
                        flush=True,
                    )
                    if self.matcher.pointer == group_start:
                        # Keep the announced second-00 anchor. Skipping a late
                        # sample must not silently desynchronize the receiver.
                        next_tick_epoch = due_tick_epoch
                        continue
                    next_tick_epoch = due_tick_epoch

                phase = now_epoch - int(now_epoch)
                if phase > UTC_MAX_SAMPLE_PHASE_SECONDS:
                    print(
                        f"Skipped late UTC tick {next_tick_epoch}; "
                        f"sample phase was {phase:.3f}s.",
                        flush=True,
                    )
                    next_tick_epoch += 1
                    continue

                group_info = {
                    "group_index": group_index,
                    "group_attempt": group_attempt,
                    "group_window_index": self.matcher.pointer - group_start,
                    "group_window_count": group_window_count,
                    "group_end": self.matcher.pointer + 1 == group_end,
                    "group_start_tick_epoch": group_start_tick_epoch,
                }
                self._process_periodic_sample(
                    self.sample_count + 1,
                    clock_tick_epoch=next_tick_epoch,
                    group_info=group_info,
                )
                next_tick_epoch += 1

                if self.matcher.pointer == group_end:
                    group_response = self.on_group_response(
                        group_index,
                        group_attempt,
                        group_window_count,
                        self.matcher.bit_length,
                    )
                    break

            if group_response is None:
                continue
            action = group_response["action"]
            response_group_index = group_response["group_index"]
            response_group_attempt = group_response["group_attempt"]
            next_group_index = group_response["next_group_index"]
            next_group_attempt = group_response["next_group_attempt"]
            resume_at_epoch = group_response["resume_at_epoch"]
            final_group = group_response["final_group"]
            if action not in ("complete", "replay"):
                raise RuntimeError(
                    f"Unknown receiver group response: {action!r}"
                )
            if (
                response_group_index < 0
                or response_group_attempt < 1
                or next_group_index < group_index
                or next_group_index > total_groups
                or next_group_attempt < 1
            ):
                raise RuntimeError("Receiver response has invalid group indexes")
            if action == "complete":
                if (
                    next_group_index != response_group_index + 1
                    or next_group_attempt != 1
                ):
                    raise RuntimeError(
                        "Complete response does not point to the next group"
                    )
                print(
                    f"Receiver confirmed group {response_group_index + 1}.",
                    flush=True,
                )
            else:
                if (
                    next_group_index != response_group_index
                    or next_group_attempt <= response_group_attempt
                ):
                    raise RuntimeError(
                        "Replay response does not point to a later attempt"
                    )
                print(
                    f"Receiver requested group {next_group_index + 1}, "
                    f"attempt {next_group_attempt}.",
                    flush=True,
                )

            if final_group:
                if action != "complete" or next_group_index != total_groups:
                    raise RuntimeError(
                        "Final response does not mark the last group complete"
                    )
                group_start = total_windows
                break
            if not is_utc_minute_anchor_epoch(resume_at_epoch):
                raise RuntimeError(
                    "Receiver response is not anchored at UTC wall-clock :00"
                )
            new_group_start = next_group_index * GROUP_WINDOW_COUNT
            if new_group_start >= total_windows:
                raise RuntimeError(
                    "Non-final response points beyond the final message window"
                )
            if new_group_start < group_start:
                raise RuntimeError("Receiver response moves the sender backward")
            group_start = new_group_start
            group_attempt = next_group_attempt
            if group_start < total_windows:
                if (
                    isinstance(resume_at_epoch, bool)
                    or not isinstance(resume_at_epoch, int)
                ):
                    raise RuntimeError(
                        "Receiver response has no integer UTC anchor"
                    )
                next_tick_epoch = resume_at_epoch

    def _start_periodic(self, start_reference):
        self.t0_wallclock = timestamp_now()
        if self.iface is None:
            print("Pointer interface: Scapy default", flush=True)
        else:
            print(
                f"Pointer interface: {describe_interface(self.iface)}",
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
        if self.matcher is not None:
            print(
                f"Bit matching active: {len(self.matcher.windows)} window(s).",
                flush=True,
            )
        print("Press Ctrl+C to stop and save results.\n", flush=True)

        if self.counter_mode in UTC_COUNTER_MODES:
            if isinstance(start_reference, bool) or not isinstance(
                start_reference, int
            ):
                raise ValueError(
                    "UTC mode requires the shared startup tick epoch"
                )
            self._utc_start_tick_epoch = start_reference
            if self.counter_mode == GROUP_MODE:
                self._start_grouped_utc(start_reference)
                return
            next_tick_epoch = start_reference
            while self.matcher is None or not self.matcher.is_complete:
                deadline = next_tick_epoch + UTC_TICK_PHASE_SECONDS
                delay = deadline - time.time()
                if delay > 0:
                    time.sleep(delay)

                now_epoch = time.time()
                due_tick_epoch = utc_tick_epoch(now_epoch)
                if due_tick_epoch < next_tick_epoch:
                    continue
                if due_tick_epoch > next_tick_epoch:
                    if self.sample_count == 0:
                        raise RuntimeError(
                            "Shared UTC start tick was missed; restart both "
                            "sender and receiver."
                        )
                    skipped = due_tick_epoch - next_tick_epoch
                    print(
                        f"Skipped {skipped} late UTC counter tick(s).",
                        flush=True,
                    )
                    next_tick_epoch = due_tick_epoch

                phase = now_epoch - int(now_epoch)
                if phase > UTC_MAX_SAMPLE_PHASE_SECONDS:
                    if self.sample_count == 0:
                        raise RuntimeError(
                            "First UTC counter tick was too late; restart both "
                            "sender and receiver."
                        )
                    print(
                        f"Skipped late UTC tick {next_tick_epoch}; "
                        f"sample phase was {phase:.3f}s.",
                        flush=True,
                    )
                    next_tick_epoch += 1
                    continue

                self._process_periodic_sample(
                    self.sample_count + 1,
                    clock_tick_epoch=next_tick_epoch,
                )
                next_tick_epoch += 1
            return

        next_tick_epoch = None
        if self.counter_mode == SYNCED_CLOCK_MODE:
            if isinstance(start_reference, bool) or not isinstance(
                start_reference, (int, float)
            ):
                raise ValueError(
                    "Synchronized clock mode requires an absolute start epoch"
                )
            next_tick_epoch = int(start_reference)
            next_tick = time.perf_counter() + max(
                0.0, next_tick_epoch - time.time()
            )
        else:
            next_tick = (
                start_reference
                if start_reference is not None
                else time.perf_counter()
            )
        while self.matcher is None or not self.matcher.is_complete:
            delay = next_tick - time.perf_counter()
            if delay > 0:
                time.sleep(delay)
            self._process_periodic_sample(
                self.sample_count + 1,
                clock_tick_epoch=next_tick_epoch,
            )
            next_tick += PERIODIC_COUNTER_INTERVAL_SECONDS
            if next_tick_epoch is not None:
                next_tick_epoch += int(PERIODIC_COUNTER_INTERVAL_SECONDS)

    def start(self):
        if self.counter_mode == SYNCED_CLOCK_MODE:
            print(
                "Periodic-B synchronized clock mode: sniffing for a broadcast "
                "ARP directly, then confirming its shared start time.",
                flush=True,
            )
        elif self.counter_mode in UTC_COUNTER_MODES:
            print(
                f"Periodic-B {self.counter_mode} mode: waiting for startup signaling, "
                "then sampling against shared UTC-second ticks. Keep both "
                "system clocks synchronized.",
                flush=True,
            )
        else:
            print(
                "Periodic-B: sending an mDNS arm, waiting for a broadcast ARP "
                "anchor, confirming it, then generating history bits from the counter.",
                flush=True,
            )
        start_reference = self.on_start()
        self._start_periodic(start_reference=start_reference)

    def save_json(self, filepath="history_results.json", verbose=True):
        output = {
            "interface": self.iface,
            "counter_mode": self.counter_mode,
            "counter_interval_seconds": PERIODIC_COUNTER_INTERVAL_SECONDS,
            "initialization_time": self.t0_wallclock,
            "total_packets": None,
            "total_counter_samples": self.sample_count,
            "samples": self.records,
        }
        with open(filepath, "w", encoding="utf-8") as handle:
            json.dump(output, handle, indent=2)
        if verbose:
            print(f"\nSaved {self.sample_count} counter sample(s) to {filepath}")


def list_interfaces():
    return get_if_list()


def describe_interface(interface_name):
    """Return a short adapter name without network address details."""
    try:
        interface = conf.ifaces.dev_from_networkname(interface_name)
    except Exception:
        return "Adapter details unavailable"

    for value in (interface.name, interface.description):
        if value and value != interface_name:
            return value
    return "Windows network adapter"
