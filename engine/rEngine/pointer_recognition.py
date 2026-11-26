"""Kenali pointer mDNS yang dibuat ``engine/sEngine/pointer_signal.py``."""

from ipaddress import IPv4Address

from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from engine.pointer_protocol import (
    MDNS_GROUP_IP,
    MDNS_PORT,
    POINTER_SERVICE_SUFFIX,
    POINTER_TXT_SIGNATURE,
)

DNS_TXT_TYPE = 16


class PointerRecognizer:
    """Validasi sumber dan TXT record pointer sebelum diteruskan ke extractor."""

    def __init__(self, sender_ip):
        """Simpan IPv4 sender agar frame pointer dari host lain diabaikan."""
        self.sender_ip = str(IPv4Address(sender_ip))

    def recognize(self, pkt):
        """Kembalikan metadata pointer valid, atau ``None`` untuk frame lain."""
        record, _reason = self.inspect(pkt)
        return record

    def inspect(self, pkt):
        """Return pointer metadata and a concise reason when a packet is rejected."""
        if not (
            pkt.haslayer(Ether)
            and pkt.haslayer(IP)
            and pkt.haslayer(UDP)
            and pkt.haslayer(DNS)
        ):
            missing = [
                layer.__name__
                for layer in (Ether, IP, UDP, DNS)
                if not pkt.haslayer(layer)
            ]
            return None, f"missing Scapy layer(s): {', '.join(missing)}"
        if pkt[IP].src != self.sender_ip:
            return None, (
                f"source IPv4 is {pkt[IP].src}; configured sender is "
                f"{self.sender_ip}"
            )
        if pkt[IP].dst != MDNS_GROUP_IP:
            return None, f"destination IPv4 is {pkt[IP].dst}, not {MDNS_GROUP_IP}"
        if pkt[UDP].sport != MDNS_PORT or pkt[UDP].dport != MDNS_PORT:
            return None, (
                f"UDP ports are {pkt[UDP].sport}->{pkt[UDP].dport}; "
                f"expected {MDNS_PORT}->{MDNS_PORT}"
            )

        dns = pkt[DNS]
        if not dns.qr:
            return None, "DNS packet is a query (QR=0), expected a response"
        if not dns.aa:
            return None, "DNS response is not authoritative (AA=0)"
        if not dns.ancount:
            return None, "DNS response has no answer records"

        pointer_metadata = self._find_pointer_txt_record(dns)
        if pointer_metadata is None:
            return None, (
                "DNS answers contain no TXT pointer record with service suffix "
                f"{POINTER_SERVICE_SUFFIX!r} and signature "
                f"{POINTER_TXT_SIGNATURE!r}"
            )

        record = {
            "packet_type": "mDNS",
            "src_ip": pkt[IP].src,
            "src_mac": pkt[Ether].src,
            "dst_ip": pkt[IP].dst,
            "dst_mac": pkt[Ether].dst,
            "src_port": pkt[UDP].sport,
            "dst_port": pkt[UDP].dport,
            "dns_record_name": pointer_metadata["name"],
            "dns_record_type": "TXT",
        }
        record.update({
            key: pointer_metadata[key]
            for key in (
                "counter_mode",
                "counter_bits",
                "tick_epoch",
                "signal_type",
                "anchor_id",
                "start_at_epoch",
            )
            if key in pointer_metadata
        })
        return record, None

    @classmethod
    def _find_pointer_txt_record(cls, dns):
        """Cari jawaban TXT dengan suffix service dan signature protokol bersama."""
        answer = dns.an
        answer_count = int(dns.ancount)
        for _ in range(answer_count):
            if not hasattr(answer, "rrname"):
                break

            record_name = cls._text(answer.rrname).rstrip(".").lower()
            record_type = int(answer.type)
            if record_type == DNS_TXT_TYPE and record_name.endswith(
                POINTER_SERVICE_SUFFIX
            ):
                fields = cls._txt_values(answer.rdata)
                has_signature = any(
                    POINTER_TXT_SIGNATURE in field.lower() for field in fields
                )
                if not has_signature:
                    answer = answer.payload
                    continue

                metadata = {"name": record_name}
                counter_mode = cls._field_value(fields, "counter_mode")
                signal_type = cls._field_value(fields, "signal_type")
                anchor_id = cls._field_value(fields, "anchor_id")
                start_at_epoch = cls._field_value(fields, "start_at_epoch")
                counter_bits = cls._field_value(fields, "counter_bits")
                tick_epoch = cls._field_value(fields, "tick_epoch")
                if counter_mode is not None:
                    metadata["counter_mode"] = counter_mode
                if signal_type is not None:
                    metadata["signal_type"] = signal_type
                if anchor_id is not None:
                    metadata["anchor_id"] = anchor_id
                if start_at_epoch is not None:
                    metadata["start_at_epoch"] = start_at_epoch
                if counter_bits is not None:
                    metadata["counter_bits"] = counter_bits
                if tick_epoch is not None:
                    metadata["tick_epoch"] = tick_epoch
                return metadata

            answer = answer.payload
        return None

    @classmethod
    def _txt_values(cls, rdata):
        """Normalisasi field TXT Scapy menjadi daftar string untuk pembacaan metadata."""
        fields = rdata if isinstance(rdata, (list, tuple)) else [rdata]
        return [cls._text(field).strip() for field in fields]

    @staticmethod
    def _field_value(fields, field_name):
        prefix = f"{field_name}="
        for field in fields:
            if field.startswith(prefix):
                return field[len(prefix):]
        return None

    @staticmethod
    def _text(value):
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)
