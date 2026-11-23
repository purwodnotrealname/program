from datetime import datetime


PERIODIC_COUNTER_INTERVAL_SECONDS = 1.0
OUTPUT_BITS = 4
PERIODIC_MODE = "periodic"
HCC_MODE = "HCC"
PERIODIC_COUNTER_MODES = (PERIODIC_MODE, HCC_MODE)
PERIODIC_COUNTER_VALUES = tuple(range(2 ** OUTPUT_BITS))


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
