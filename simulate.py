#!/usr/bin/env python3
"""Генератор атакующего трафика для демо. Шлёт настоящие пакеты (скан портов,
свип хостов, DNS-эксфильтрация, одиночный коннект), чтобы движок было на чём
проверить. Посредством обычных сокетов ОС — трафик реально идёт через ядро (и
наш NFQUEUE), так что `drop`-правило его действительно роняет.

Цели в 127.0.0.0/8 указывают на сам хост, поэтому пакеты проходят через lo:
  * защита выключена -> закрытый порт сразу отвечает (Connection refused)
  * защита включена  -> SYN дропается -> connect() висит / отваливается по таймауту

  python simulate.py port-scan          # много портов на 127.0.0.1
  python simulate.py sweep              # много хостов 127.0.0.x
  python simulate.py dns-evil           # UDP DNS-пакет со строкой "evil"
  python simulate.py connect --target 127.0.0.1 --port 445   # одиночная проба
"""

import argparse
import socket
import sys
import time

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445,
                636, 993, 995, 1433, 3306, 3389, 5432, 5985, 5986, 8000, 8080,
                8443, 9000, 9090, 9200, 27017, 6379]


def _tcp_probe(host: str, port: int, timeout: float) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    start = time.monotonic()
    try:
        rc = s.connect_ex((host, port))
        elapsed = time.monotonic() - start
        if rc == 0:
            return f"open ({elapsed:.2f}s)"
        return f"refused ({elapsed:.2f}s)"
    except socket.timeout:
        return f"TIMEOUT/blocked ({time.monotonic()-start:.2f}s)"
    finally:
        s.close()


def port_scan(args) -> None:
    print(f"[*] Port scan {args.target}: {len(COMMON_PORTS)} ports")
    for p in COMMON_PORTS:
        _tcp_probe(args.target, p, args.timeout)
        time.sleep(args.delay)


def sweep(args) -> None:
    base = args.target.rsplit(".", 1)[0]
    hosts = [f"{base}.{i}" for i in range(1, args.count + 1)]
    print(f"[*] Host sweep: {len(hosts)} hosts on port {args.port}")
    for h in hosts:
        _tcp_probe(h, args.port, args.timeout)
        time.sleep(args.delay)


def dns_evil(args) -> None:
    # Minimal DNS query for "login.evil.example.com" (qname has the label "evil").
    qname = b"".join(bytes([len(p)]) + p.encode()
                     for p in "login.evil.example.com".split(".")) + b"\x00"
    packet = (b"\x13\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
              + qname + b"\x00\x01\x00\x01")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(packet, (args.target, 53))
    s.close()
    print(f"[*] Sent DNS query containing 'evil' to {args.target}:53")


def dns_tunnel(args) -> None:
    # DNS TXT query whose qname carries a shell command + a long base64 blob —
    # the shape of DNS tunneling / C2.  The DPI inspector (sid 3001) blocks it.
    blob = "powershell-" + "QWxhZGRpbjpvcGVuc2VzYW1lQWxhZGRpbg"  # ~45-char label
    labels = [blob, "tunnel", "c2", "example", "net"]
    qname = b"".join(bytes([len(l)]) + l.encode() for l in labels) + b"\x00"
    packet = (b"\x13\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
              + qname + b"\x00\x10\x00\x01")  # qtype TXT(16), qclass IN(1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(packet, (args.target, 53))
    s.close()
    print(f"[*] Sent DNS TXT tunneling query to {args.target}:53 (DPI should drop)")


def connect(args) -> None:
    result = _tcp_probe(args.target, args.port, args.timeout)
    print(f"[*] {args.target}:{args.port} -> {result}")


SCENARIOS = {
    "port-scan": port_scan,
    "sweep": sweep,
    "dns-evil": dns_evil,
    "dns-tunnel": dns_tunnel,
    "connect": connect,
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="NIDS/IPS attack generator (real sockets)")
    p.add_argument("scenario", choices=list(SCENARIOS), help="Attack to run")
    p.add_argument("--target", default="127.0.0.1", help="Target host")
    p.add_argument("--port", type=int, default=80, help="Port (sweep/connect)")
    p.add_argument("--count", type=int, default=15, help="Hosts for sweep")
    p.add_argument("--timeout", type=float, default=1.5, help="Connect timeout (s)")
    p.add_argument("--delay", type=float, default=0.03, help="Delay between probes")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    SCENARIOS[args.scenario](args)


if __name__ == "__main__":
    main()
