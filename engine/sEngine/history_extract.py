"""Generate sender history bits from a packet-independent periodic counter."""

import json
import time

from scapy.all import conf, get_if_list

from engine.periodic_counter import (
    OUTPUT_BITS,
    PERIODIC_COUNTER_INTERVAL_SECONDS,
    PERIODIC_MODE,
    SYNCED_CLOCK_MODE,
    UTC_MODE,
    UTC_MAX_SAMPLE_PHASE_SECONDS,
    UTC_TICK_PHASE_SECONDS,
    PeriodicCounterState,
    counter_for_utc_tick,
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
        counter_mode=PERIODIC_MODE,
    ):
        if counter_mode not in (PERIODIC_MODE, SYNCED_CLOCK_MODE, UTC_MODE):
            raise ValueError(
                "ICDExtractor supports legacy, synchronized clock, or UTC mode"
            )
        if not callable(on_start):
            raise ValueError("Periodic-B requires an on_start pointer callback")

        self.iface = iface
        self.counter_mode = counter_mode
        self.matcher = matcher
        self.on_match = on_match
        self.on_start = on_start
        self.records = []
        self.sample_count = 0
        self.t0_wallclock = None
        self._counter_state = PeriodicCounterState()
        self._utc_start_tick_epoch = None

    def _process_periodic_sample(self, sample_no, clock_tick_epoch=None):
        if self.counter_mode == UTC_MODE and clock_tick_epoch is not None:
            if self._utc_start_tick_epoch is None:
                raise RuntimeError("UTC start tick has not been initialized")
            counter = counter_for_utc_tick(
                clock_tick_epoch,
                self._utc_start_tick_epoch,
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
        if self.matcher is not None and not self.matcher.is_complete:
            attempt = self.matcher.try_match(
                bit_value=counter,
                sample_no=sample_no,
            )
            attempt["counter_mode"] = self.counter_mode

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
                    self.on_match({**attempt, "sample": record})
                except Exception as exc:
                    print(f"       - pointer signal failed: {exc}", flush=True)

    def _start_periodic(self, start_reference):
        self.t0_wallclock = timestamp_now()
        if self.iface is None:
            print("Pointer interface: Scapy default", flush=True)
        else:
            print(
                f"Pointer interface: {describe_interface(self.iface)}",
                flush=True,
            )
        if self.counter_mode == UTC_MODE:
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

        if self.counter_mode == UTC_MODE:
            if isinstance(start_reference, bool) or not isinstance(
                start_reference, int
            ):
                raise ValueError(
                    "UTC mode requires the shared startup tick epoch"
                )
            self._utc_start_tick_epoch = start_reference
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
        elif self.counter_mode == UTC_MODE:
            print(
                "Periodic-B UTC-derived mode: waiting for startup signaling, "
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
