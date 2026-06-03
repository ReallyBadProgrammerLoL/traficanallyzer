#!/usr/bin/env python3
"""Точка входа для консоли / оффлайн-анализа. Гоняет тот же Controller/Engine,
что и живой дашборд, но для консоли и replay pcap. Посредством sniffer (live)
или чтения pcap-файла Scapy.

    main.py --pcap attack.pcap            # разобрать дамп, алерты в stdout
    main.py --pcap attack.pcap --web      # …и поднять дашборд
    main.py -i lo                         # живой мониторинг интерфейса (без IPS)

Для полного inline-IPS с веб-управлением — app.py (./start.sh). Этот путь
блокировку не включает: только monitor/анализ.
"""

import argparse
import signal
import sys
import time

import sniffer
import decoder
from controller import Controller


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Python NIDS — console / pcap analysis")
    p.add_argument("-i", "--iface", default="lo",
                   help="Interface to sniff live (default: lo)")
    p.add_argument("-p", "--pcap", default=None,
                   help="Read packets from a pcap file instead of live capture")
    p.add_argument("-r", "--rules", default="rules.txt",
                   help="Path to rules file (default: rules.txt)")
    p.add_argument("-o", "--output", default="alerts.json",
                   help="JSON Lines alert log (default: alerts.json)")
    p.add_argument("--home-net", action="append", metavar="CIDR", default=None,
                   help="Only inspect traffic to/from this subnet "
                        "(repeatable, e.g. --home-net 10.0.0.0/24)")
    p.add_argument("--web", action="store_true", help="Start the live web dashboard")
    p.add_argument("--host", default="127.0.0.1", help="Dashboard host")
    p.add_argument("--port", type=int, default=8080, help="Dashboard port")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    ctrl = Controller(args.rules, args.output, iface=args.iface)
    if not ctrl.store.rules:
        sys.exit("[!] No rules loaded — check rules.txt")
    if args.home_net:
        ctrl.set_scope(home_net=args.home_net)
        print(f"[*] HOME_NET filter: {', '.join(args.home_net)}", file=sys.stderr)

    if args.web:
        import web  # lazy import so Flask is optional without --web
        web.run_in_thread(ctrl, host=args.host, port=args.port)
        print(f"[*] Dashboard: http://{args.host}:{args.port}", file=sys.stderr)

    def shutdown(sig, frame) -> None:
        print("\n[*] Shutting down…", file=sys.stderr)
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    if args.pcap:
        def feed(pkt) -> None:
            rec = decoder.decode(pkt)
            if rec is not None:
                ctrl.engine.process(rec)
        sniffer.replay(args.pcap, feed)
        if args.web:
            print("[*] Replay done — dashboard still serving. Ctrl+C to exit.",
                  file=sys.stderr)
            while True:
                time.sleep(1)
    else:
        ctrl.start()  # live monitor (no blocking)
        while True:
            time.sleep(1)


if __name__ == "__main__":
    main()
