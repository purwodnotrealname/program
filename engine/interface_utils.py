"""Pilihan adapter bersama yang dipakai entry point sender dan receiver."""

from scapy.all import conf, get_if_list

from engine.periodic_counter import (
    PERIODIC_MODE,
    SYNCED_CLOCK_MODE,
    TRIGGERED_MDNS_MODE,
    UTC_MODE,
)


def list_interfaces():
    """Ambil identifier adapter yang akan diberikan ke Scapy."""
    return get_if_list()


def describe_interface(interface_name):
    """Ambil label singkat adapter untuk tampilan, tanpa alamat jaringan."""
    try:
        interface = conf.ifaces.dev_from_networkname(interface_name)
    except Exception:
        return "Adapter details unavailable"

    for value in (interface.name, interface.description):
        if value and value != interface_name:
            return value
    return "Windows network adapter"


def choose_network_interface(prompt):
    """Tampilkan nama adapter, validasi indeks, lalu kembalikan identifier Scapy.

    Fungsi ini menggantikan pemilih yang sebelumnya terduplikasi di kedua
    entry point utama.
    """
    interfaces = list_interfaces()
    if not interfaces:
        print("No network interfaces found")
        raise SystemExit(1)

    print("Available network interfaces:")
    for index, interface_name in enumerate(interfaces):
        print(f"  [{index}] {describe_interface(interface_name)}")

    while True:
        choice = input(prompt).strip()
        try:
            index = int(choice)
            if not 0 <= index < len(interfaces):
                raise IndexError
            return interfaces[index]
        except (ValueError, IndexError):
            print("Invalid selection. Enter one of the listed indexes.")


def choose_counter_mode():
    """Let sender and receiver select the same counter clock strategy."""
    print("Counter modes:")
    print("  [1] Legacy: counter starts from the observed ARP packet")
    print(
        "  [2] Synchronized clock: sniff ARP directly (no initial mDNS arm), "
        "then start at the next minute boundary; sync both clocks and start "
        "receiver first"
    )
    print(
        "  [3] UTC-derived: counter is the Unix UTC second modulo 16; "
        "keep both system clocks synchronized and start receiver first"
    )
    print(
        "  [4] Triggered mDNS: use Windows DNS-SD probes as pointer bursts; "
        "keep both system clocks synchronized and start receiver first"
    )
    while True:
        choice = input(
            "Select counter mode (sender and receiver must choose the same): "
        ).strip()
        if choice == "1":
            return PERIODIC_MODE
        if choice == "2":
            return SYNCED_CLOCK_MODE
        if choice == "3":
            return UTC_MODE
        if choice == "4":
            return TRIGGERED_MDNS_MODE
        print("Invalid selection. Enter 1, 2, 3, or 4.")
