import time
from datetime import datetime, timedelta, timezone


PERIODIC_COUNTER_INTERVAL_SECONDS = 1.0
OUTPUT_BITS = 4
PERIODIC_MODE = "periodic"
SYNCED_CLOCK_MODE = "synced_clock"
UTC_MODE = "utc_clock"
GROUP_MODE = "utc_group"
UTC_COUNTER_MODES = (UTC_MODE, GROUP_MODE)
GROUP_BITS = 100
GROUP_WINDOW_COUNT = GROUP_BITS // OUTPUT_BITS
GROUP_RETRY_SILENCE_SECONDS = 24
GROUP_RETRY_TIMEOUT_SECONDS = GROUP_RETRY_SILENCE_SECONDS
HCC_MODE = "HCC"
PERIODIC_COUNTER_MODES = (
    PERIODIC_MODE,
    SYNCED_CLOCK_MODE,
    *UTC_COUNTER_MODES,
    HCC_MODE,
)
PERIODIC_COUNTER_VALUES = tuple(range(2 ** OUTPUT_BITS))
UTC_TICK_PHASE_SECONDS = 0.0
UTC_MAX_SAMPLE_PHASE_SECONDS = 0.65
UTC_START_LEAD_TICKS = 4
UTC_POINTER_SEND_MIN_PHASE_SECONDS = 0.30
UTC_POINTER_SEND_MAX_PHASE_SECONDS = 0.70


def next_counter_zero_tick_epoch(start_tick_epoch, timestamp=None):
    """Return the next future UTC tick whose run-relative counter is zero."""
    if timestamp is None:
        timestamp = time.time()
    tick_epoch = next_utc_tick_epoch(timestamp)
    remainder = (tick_epoch - start_tick_epoch) % len(PERIODIC_COUNTER_VALUES)
    return tick_epoch + (-remainder) % len(PERIODIC_COUNTER_VALUES)


def counter_zero_tick_epoch_at_or_after(start_tick_epoch, earliest_tick_epoch):
    """Return the first shared counter-0000 tick at or after an epoch."""
    for name, value in (
        ("start_tick_epoch", start_tick_epoch),
        ("earliest_tick_epoch", earliest_tick_epoch),
    ):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} must be an integer UTC second")
    remainder = (
        earliest_tick_epoch - start_tick_epoch
    ) % len(PERIODIC_COUNTER_VALUES)
    return earliest_tick_epoch + (-remainder) % len(PERIODIC_COUNTER_VALUES)


def next_minute_epoch(timestamp=None):
    """Return the next absolute minute boundary after a Unix timestamp."""
    if timestamp is None:
        timestamp = time.time()
    return (int(timestamp) // 60 + 1) * 60


def next_utc_minute_anchor_epoch(timestamp=None):
    """Return the next UTC wall-clock minute start (seconds field ``00``)."""
    if timestamp is None:
        timestamp = time.time()
    current = datetime.fromtimestamp(timestamp, timezone.utc)
    next_minute = (
        current.replace(second=0, microsecond=0)
        + timedelta(minutes=1)
    )
    return int(next_minute.timestamp())


def is_utc_minute_anchor_epoch(epoch):
    """Return whether an integer epoch represents UTC with seconds ``00``."""
    if isinstance(epoch, bool) or not isinstance(epoch, int):
        return False
    anchor_time = datetime.fromtimestamp(epoch, timezone.utc)
    return anchor_time.second == 0 and anchor_time.microsecond == 0


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
