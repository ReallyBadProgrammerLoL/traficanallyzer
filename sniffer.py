"""Модуль 1 — захват пакетов. Снимает трафик с интерфейса или из pcap-файла.
Посредством Scapy (sniff)."""

import sys
from scapy.all import sniff, conf


def start(iface: str, callback) -> None:
    """Capture packets live on *iface*, calling *callback* for each."""
    conf.verb = 0  # silence Scapy startup noise
    print(f"[*] Sniffing on {iface} — Ctrl+C to stop", file=sys.stderr)
    try:
        sniff(iface=iface, prn=callback, store=False)
    except PermissionError:
        sys.exit("[!] Run with sudo — raw socket needs root")
    except OSError as exc:
        sys.exit(f"[!] Cannot open interface '{iface}': {exc}")


def replay(pcap_path: str, callback) -> None:
    """Read packets from a pcap file (no root, deterministic)."""
    conf.verb = 0
    print(f"[*] Replaying {pcap_path}", file=sys.stderr)
    try:
        sniff(offline=pcap_path, prn=callback, store=False)
    except FileNotFoundError:
        sys.exit(f"[!] pcap not found: {pcap_path}")
    print("[*] Replay finished", file=sys.stderr)
