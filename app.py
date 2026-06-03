#!/usr/bin/env python3
"""Точка входа — живой NIDS/IPS с веб-плоскостью управления. Поднимает контроллер
и дашборд, дальше всё управляется из UI. Посредством Controller + Flask
(web.run_in_thread).

Стартует в безопасном idle (firewall не трогается); monitor/protect для выбранного
интерфейса включаются из дашборда. Для оффлайн-анализа pcap используйте main.py.
"""

import argparse
import signal
import sys
import time

import web
from controller import Controller


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Python NIDS/IPS control-plane")
    p.add_argument("-i", "--iface", default="lo", help="Initial interface (default: lo)")
    p.add_argument("-r", "--rules", default="rules.txt", help="Rules file")
    p.add_argument("-o", "--output", default="alerts.json", help="JSON Lines log")
    p.add_argument("--queue", type=int, default=1, help="NFQUEUE number")
    p.add_argument("--host", default="127.0.0.1", help="Dashboard host")
    p.add_argument("--port", type=int, default=8080, help="Dashboard port")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    ctrl = Controller(args.rules, args.output, iface=args.iface, queue_num=args.queue)

    web.run_in_thread(ctrl, host=args.host, port=args.port)
    ctrl.start()

    print(f"[*] Dashboard: http://{args.host}:{args.port}", file=sys.stderr)
    print("[*] Mode: IDLE (no capture). Start Monitor or Protection from the UI.",
          file=sys.stderr)

    def shutdown(sig, frame) -> None:
        print("\n[*] Shutting down…", file=sys.stderr)
        ctrl.disable_protection()  # tears down firewall if it was on
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
