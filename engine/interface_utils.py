"""Pilihan adapter bersama yang dipakai entry point sender dan receiver."""

from scapy.all import conf, get_if_list


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
