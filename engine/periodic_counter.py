import time
from datetime import datetime


PERIODIC_COUNTER_INTERVAL_SECONDS = 1.0
OUTPUT_BITS = 4
PERIODIC_MODE = "periodic"
SYNCED_CLOCK_MODE = "synced_clock"
UTC_MODE = "utc_clock"
HCC_MODE = "HCC"
PERIODIC_COUNTER_MODES = (
    PERIODIC_MODE,
    SYNCED_CLOCK_MODE,
    UTC_MODE,
    HCC_MODE,
)
PERIODIC_COUNTER_VALUES = tuple(range(2 ** OUTPUT_BITS))
UTC_TICK_PHASE_SECONDS = 0.0
UTC_MAX_SAMPLE_PHASE_SECONDS = 0.65
UTC_START_LEAD_TICKS = 4
UTC_POINTER_SEND_MIN_PHASE_SECONDS = 0.30
UTC_POINTER_SEND_MAX_PHASE_SECONDS = 0.70


def next_minute_epoch(timestamp=None):
    """Return the next absolute minute boundary after a Unix timestamp."""
    if timestamp is None:
        timestamp = time.time()
    return (int(timestamp) // 60 + 1) * 60


def utc_tick_epoch(timestamp=None):
    """Return the UTC second currently active after the configured tick phase."""
    if timestamp is None:
        timestamp = time.time()
    return int(timestamp - UTC_TICK_PHASE_SECONDS)


def next_utc_tick_epoch(timestamp=None):
    """Return the next UTC second whose phased tick has not started yet."""
    return utc_tick_epoch(timestamp) + 1


def counter_for_utc_tick(tick_epoch, start_tick_epoch=0):
    """Return the 4-bit value relative to this run's shared start tick."""
    if isinstance(tick_epoch, bool) or not isinstance(tick_epoch, int):
        raise TypeError("tick_epoch must be an integer UTC second")
    if (
        isinstance(start_tick_epoch, bool)
        or not isinstance(start_tick_epoch, int)
    ):
        raise TypeError("start_tick_epoch must be an integer UTC second")
    return (tick_epoch - start_tick_epoch) % len(PERIODIC_COUNTER_VALUES)


class PeriodicCounterState:
    """Cycle through the 16 four bit values on a periodic timer."""

    def __init__(self):
        self.index = 0

    def next_value(self):
        value = PERIODIC_COUNTER_VALUES[self.index]
        self.index = (self.index + 1) % len(PERIODIC_COUNTER_VALUES)
        return value

def timestamp_now():
    return datetime.now().isoformat(timespec="milliseconds")
