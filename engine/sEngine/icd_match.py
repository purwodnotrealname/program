from .history_match import (
    SequentialBitMatcher as _SequentialBitMatcher,
    split_message_windows,
)

class SequentialBitMatcher(_SequentialBitMatcher):
    def save_json(self, filepath="icd_match_results.json"):
        return super().save_json(filepath)
