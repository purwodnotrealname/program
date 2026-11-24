"""Entry point sender: kumpulkan bit pesan lalu hubungkan counter, matcher, dan sinyal mDNS.

Logika sampling ada di ``engine/sEngine/history_extract.py``; pencocokan bit
ada di ``engine/sEngine/history_match.py``; dan paket pointer dikirim oleh
``engine/sEngine/pointer_signal.py``.
"""

from pathlib import Path

from engine.sEngine.history_extract import ICDExtractor
from engine.sEngine.history_match import SequentialBitMatcher
from engine.sEngine.pointer_signal import PointerSignalSender
from engine.interface_utils import choose_counter_mode, choose_network_interface
from engine.periodic_counter import OUTPUT_BITS

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_FILE = str(BASE_DIR / "engineDump" / "history_results.json")
MATCH_OUTPUT_FILE = str(BASE_DIR / "engineDump" / "history_match_results.json")


def choose_message_bits():
    """Validasi masukan biner dan siapkan bentuk integer serta teksnya."""
    while True:
        entered = input(
            "Enter message bits (0/1; spaces, underscores, and 0b prefix are optional): "
        )
        message_bits = "".join(entered.split()).replace("_", "")
        if message_bits.lower().startswith("0b"):
            message_bits = message_bits[2:]

        if not message_bits:
            print("Message cannot be empty. Enter at least one bit.")
            continue
        if any(bit not in "01" for bit in message_bits):
            print("Invalid message. Enter only 0 and 1.")
            continue

        return int(message_bits, 2), len(message_bits), message_bits


def main():
    """Rangkai komponen sender melalui callback dan simpan hasil run."""
    message_value, message_bit_length, message_bits = choose_message_bits()
    iface = choose_network_interface(
        "\nSelect the adapter for capture or pointer signals: "
    )
    counter_mode = choose_counter_mode()

    signal_sender = PointerSignalSender(
        iface=iface,
        message_bits=message_bits,
        counter_mode=counter_mode,
    )
    matcher = SequentialBitMatcher(
        message_value,
        bit_length=message_bit_length,
        window_size=OUTPUT_BITS,
        input_bit_width=OUTPUT_BITS,
    )
    extractor = ICDExtractor(
        iface=iface,
        matcher=matcher,
        on_match=signal_sender.send_for_match,
        on_start=signal_sender.send_start_signal,
        counter_mode=counter_mode,
    )

    try:
        extractor.start()
    except KeyboardInterrupt:
        pass
    finally:
        extractor.save_json(OUTPUT_FILE)
        matcher.save_json(MATCH_OUTPUT_FILE)
        if matcher.is_complete:
            print(
                f"\nevery {len(matcher.windows)} window successfully matched. "
                "Periodic-B run terminated."
            )
        else:
            print(
                "\nPeriodic-B run terminated. Progress: "
                f"{matcher.match_count}/{len(matcher.windows)} windows matched."
            )


if __name__ == "__main__":
    main()
