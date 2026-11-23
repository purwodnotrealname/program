"""Generate sender history bits from a packet-independent periodic counter."""

import json
import time

from scapy.all import conf, get_if_list

from engine.periodic_counter import (
    OUTPUT_BITS,
    PERIODIC_COUNTER_INTERVAL_SECONDS,
    PERIODIC_MODE,
    PeriodicCounterState,
    timestamp_now,
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
        if counter_mode != PERIODIC_MODE:
            raise ValueError("ICDExtractor only supports the periodic counter")
        if not callable(on_start):
            raise ValueError("Periodic-B requires an on_start pointer callback")

        self.iface = iface
        self.counter_mode = PERIODIC_MODE
        self.matcher = matcher
        self.on_match = on_match
        self.on_start = on_start
        self.records = []
        self.sample_count = 0
        self.t0_wallclock = None
        self._counter_state = PeriodicCounterState()

    def _process_periodic_sample(self, sample_no):
        counter = self._counter_state.next_value()
        record = {
            "sample_no": sample_no,
            "protocol": "PERIODIC",
            "counter_mode": self.counter_mode,
            "timestamp": timestamp_now(),
            "counter": counter,
            "bit_value": counter,
        }
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

    def _start_periodic(self, start_at):
        self.t0_wallclock = timestamp_now()
        if self.iface is None:
            print("Pointer interface: Scapy default", flush=True)
        else:
            print(
                f"Pointer interface: {describe_interface(self.iface)}",
                flush=True,
            )
        print(
            "Counter mode: periodic, packet independent "
            f"(interval {PERIODIC_COUNTER_INTERVAL_SECONDS:g} seconds).",
            flush=True,
        )
        if self.matcher is not None:
            print(
                f"Bit matching active: {len(self.matcher.windows)} window(s).",
                flush=True,
            )
        print("Press Ctrl+C to stop and save results.\n", flush=True)

        next_tick = start_at or time.perf_counter()
        while self.matcher is None or not self.matcher.is_complete:
            delay = next_tick - time.perf_counter()
            if delay > 0:
                time.sleep(delay)
            self._process_periodic_sample(self.sample_count + 1)
            next_tick = max(
                next_tick + PERIODIC_COUNTER_INTERVAL_SECONDS,
                time.perf_counter() + PERIODIC_COUNTER_INTERVAL_SECONDS,
            )

    def start(self):
        print(
            "Periodic-B: sending startup pointer, then generating history bits "
            "from the periodic counter without observing PoI.",
            flush=True,
        )
        start_at = self.on_start()
        self._start_periodic(start_at=start_at)

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
