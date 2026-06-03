"""Рантайм-контроллер — владеет движком и переключает режимы захвата.
Посредством AsyncSniffer (monitor) и InlineIPS + Firewall (protect).

    idle     (по умолчанию):  захвата нет, ничего не обрабатывается.
    monitor  (безопасный):    пассивный AsyncSniffer, только алерты, firewall не трогается.
    protect  (по запросу):    inline NFQUEUE + iptables, реально РОНЯЕТ пакеты.

Protection выключена на старте, чтобы запуск приложения не рвал сеть. Оператор
включает её для выбранного интерфейса из веб-интерфейса.
"""

from __future__ import annotations
import sys
import threading

from scapy.all import AsyncSniffer

import decoder
from rule_parser import RuleStore
from dpi import DPIStore
from analyzer import ScanDetector, ScanStore
from engine import Engine
from alerting import Alerter, Hub, stdout_sink, make_jsonl_sink
from firewall import Firewall
from inline import InlineIPS


class Controller:
    def __init__(self, rules_path: str, alert_log: str = "alerts.json",
                 iface: str = "lo", queue_num: int = 1,
                 dpi_path: str = "dpi.json", scan_path: str = "scan.json") -> None:
        self.store = RuleStore(rules_path)
        self.dpi_store = DPIStore(dpi_path)
        self.scan_store = ScanStore(scan_path)
        self.hub = Hub()                 # security alerts
        self.traffic = Hub()             # every packet (live traffic feed)
        self.alerter = Alerter([stdout_sink, make_jsonl_sink(alert_log), self.hub.publish])
        self.engine = Engine(self.store, self.alerter,
                             scan=ScanDetector(**self.scan_store.config),
                             dpi_store=self.dpi_store)
        self.engine.traffic_sink = self.traffic.publish
        self.firewall = Firewall(queue_num)
        self.inline = InlineIPS(self.engine, queue_num)

        self.iface = iface
        self.home_net: list[str] = []
        self.mode = "idle"               # idle | monitor | protect
        self._sniffer: AsyncSniffer | None = None
        self._lock = threading.Lock()

    # --- capture ----------------------------------------------------------
    def _handle(self, pkt) -> None:
        rec = decoder.decode(pkt)
        if rec is not None:
            self.engine.process(rec)  # monitor mode: verdict is advisory only

    def _start_sniffer(self) -> None:
        self._sniffer = AsyncSniffer(iface=self.iface, prn=self._handle, store=False)
        self._sniffer.start()
        print(f"[*] monitor: sniffing {self.iface}", file=sys.stderr)

    def _stop_sniffer(self) -> None:
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

    def start(self) -> None:
        """Idle at startup — no capture until the operator asks for it."""
        print("[*] IDLE (no capture). Enable Monitor or Protection from the UI.",
              file=sys.stderr)

    # --- operator actions -------------------------------------------------
    def set_scope(self, iface: str | None = None,
                  home_net: list[str] | None = None,
                  default_policy: str | None = None) -> None:
        with self._lock:
            if default_policy is not None:
                self.engine.set_default_policy(default_policy)
            if home_net is not None:
                self.home_net = home_net
                self.engine.set_home_net(home_net)
            if iface and iface != self.iface:
                self.iface = iface
                if self.mode == "protect":
                    self._reprotect_locked()
                elif self.mode == "monitor":
                    self._stop_sniffer()
                    self._start_sniffer()

    def enable_monitor(self) -> None:
        with self._lock:
            if self.mode != "idle":
                return                    # already monitoring or protecting
            self._start_sniffer()
            self.mode = "monitor"

    def disable_monitor(self) -> None:
        with self._lock:
            if self.mode != "monitor":
                return
            self._stop_sniffer()
            self.mode = "idle"
            print("[*] IDLE (monitor off)", file=sys.stderr)

    def enable_protection(self) -> None:
        with self._lock:
            if self.mode == "protect":
                return
            self._stop_sniffer()          # NFQUEUE takes over capture
            self.firewall.enable(self.iface)
            self.inline.start()
            self.engine.set_protection(True)
            self.mode = "protect"
            print(f"[*] PROTECT mode on {self.iface}", file=sys.stderr)

    def disable_protection(self) -> None:
        with self._lock:
            if self.mode != "protect":
                return
            self.engine.set_protection(False)
            self.inline.stop()
            self.firewall.clear()
            self.mode = "idle"
            print("[*] IDLE (protection off)", file=sys.stderr)

    def _reprotect_locked(self) -> None:
        self.inline.stop()
        self.firewall.clear()
        self.firewall.enable(self.iface)
        self.inline.start()

    def reload_rules(self) -> None:
        self.engine.reload_rules()

    def dpi_config(self) -> dict:
        return self.dpi_store.raw()

    def save_dpi(self, data: dict) -> list[str]:
        errors = self.dpi_store.save(data)
        if not errors:
            self.engine.reload_dpi()
        return errors

    def scan_config(self) -> dict:
        return self.scan_store.raw()

    def save_scan(self, data: dict) -> list[str]:
        errors = self.scan_store.save(data)
        if not errors:
            self.engine.configure_scan(self.scan_store.config)
        return errors

    def status(self) -> dict:
        return {
            "mode": self.mode,
            "iface": self.iface,
            "protection": self.engine.protection,
            "default_policy": self.engine.default_policy,
            "home_net": self.home_net,
            "counters": self.engine.snapshot(),
            "rules": len(self.store.rules),
        }
