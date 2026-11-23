"""Entry point receiver untuk memilih adapter, alamat sender, lalu mulai capture.

Pemrosesan pointer mDNS, periodic counter, buffer, dan penggabungan bit dilakukan
oleh modul-modul di ``engine/rEngine``.
"""

from ipaddress import IPv4Address
from pathlib import Path

from engine.rEngine.history_extract import ReceiverHistoryExtractor
from engine.interface_utils import choose_network_interface


BASE_DIR = Path(__file__).resolve().parent
RECEIVER_LOG_DIR = BASE_DIR / "engine" / "rEngine" / "receiverlogdump"
PERIODIC_B_BUFFER_FILE = RECEIVER_LOG_DIR / "receiver_periodic_b_history_buffer.json"
PERIODIC_B_LOG_FILE = RECEIVER_LOG_DIR / "receiver_periodic_b_history.log"
SECRET_BITS_FILE = RECEIVER_LOG_DIR / "receiver_secret_bits.json"


def choose_pointer_source_ip():
    """Validasi IPv4 sender yang dipakai PointerRecognizer sebagai filter sumber."""
    while True:
        entered = input(
            "Enter the sender's IPv4 address for pointer recognition: "
        ).strip()
        try:
            return str(IPv4Address(entered))
        except ValueError:
            print("Invalid IPv4 address. Enter the sender's interface address.")


def main():
    """Buat receiver Periodic-B dengan buffer, log, dan secret bits."""
    iface = choose_network_interface(
        "\nSelect the adapter index to capture on: "
    )
    pointer_source_ip = choose_pointer_source_ip()
    receiver = ReceiverHistoryExtractor(
        iface=iface,
        buffer_path=PERIODIC_B_BUFFER_FILE,
        log_path=PERIODIC_B_LOG_FILE,
        secret_bits_path=SECRET_BITS_FILE,
        pointer_source_ip=pointer_source_ip,
    )

    try:
        receiver.start()
    except KeyboardInterrupt:
        print("\nSniffing stopped by user.", flush=True)


if __name__ == "__main__":
    main()
