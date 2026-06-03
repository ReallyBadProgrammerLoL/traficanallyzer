"""Модуль 2 — декодирование. Превращает пакет Scapy в плоский dict
(proto / ip / порты / флаги / payload / len). Посредством слоёв Scapy
(IP / TCP / UDP / ICMP)."""

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether


def decode(pkt) -> dict | None:
    """Return a protocol-agnostic dict or None if packet is not IP."""
    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    record = {
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "proto": None,
        "src_port": None,
        "dst_port": None,
        "flags": None,
        "payload": b"",
        "len": int(getattr(ip, "len", 0) or 0),  # IP total length (on-wire size)
    }

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        record.update(
            proto="tcp",
            src_port=tcp.sport,
            dst_port=tcp.dport,
            flags=str(tcp.flags),
            payload=bytes(tcp.payload),
        )
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        record.update(
            proto="udp",
            src_port=udp.sport,
            dst_port=udp.dport,
            payload=bytes(udp.payload),
        )
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        record.update(
            proto="icmp",
            payload=bytes(icmp.payload),
        )
    else:
        return None  # skip non-TCP/UDP/ICMP

    return record
