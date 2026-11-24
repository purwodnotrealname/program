"""Helpers for identifying a broadcast ARP frame as a shared run anchor."""

from hashlib import sha256

from scapy.layers.l2 import ARP, Ether


ARP_ANCHOR_FILTER = "(arp and ether broadcast)"


def get_arp_anchor(packet):
    """Return stable metadata for a broadcast ARP frame, or ``None``."""
    if not packet.haslayer(Ether) or not packet.haslayer(ARP):
        return None

    ethernet = packet[Ether]
    arp = packet[ARP]
    if ethernet.dst.lower() != "ff:ff:ff:ff:ff:ff":
        return None

    fields = (
        ethernet.src.lower(),
        ethernet.dst.lower(),
        str(int(arp.op)),
        arp.hwsrc.lower(),
        arp.psrc,
        arp.hwdst.lower(),
        arp.pdst,
    )
    anchor_id = sha256("|".join(fields).encode("ascii")).hexdigest()[:20]
    return {
        "anchor_id": anchor_id,
        "operation": int(arp.op),
        "src_mac": ethernet.src.lower(),
        "src_ip": arp.psrc,
        "target_mac": arp.hwdst.lower(),
        "target_ip": arp.pdst,
    }
