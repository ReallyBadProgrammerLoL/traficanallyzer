"""Движок детекции — превращает декодированный пакет в вердикт + алерты.
Объединяет сигнатуры (detector), стейтфул-анализ (analyzer) и DPI (dpi),
применяет семантику действий Snort и решает accept/drop. Посредством общего
gate'а protection (в monitor вердикт совещательный, в protect — реальный).

Приоритет действий на пакет:
    pass   -> сразу accept, без алертов (whitelist)
    drop   -> drop при включённой protection, иначе accept + флаг "would-block"
    alert  -> accept, флаг оператору
"""

from __future__ import annotations
import ipaddress
import threading

from rule_parser import RuleStore
from detector import Detector
from analyzer import ScanDetector
from dpi import DPIInspector, DPIStore
from alerting import Alerter, build_traffic


class _DefaultDeny:
    """Synthetic finding raised when default-deny drops unmatched traffic."""
    sid = 9999
    msg = "Default-deny policy (no matching pass rule)"
    category = "policy"
    action = "drop"


_DENY_FINDING = _DefaultDeny()


class Engine:
    def __init__(self, store: RuleStore, alerter: Alerter,
                 scan: ScanDetector | None = None,
                 dpi_store: DPIStore | None = None) -> None:
        self._store = store
        self._alerter = alerter
        self._scan = scan or ScanDetector()
        self._dpi = DPIInspector(dpi_store)
        self._lock = threading.RLock()
        self._detector = Detector(store.rules)

        self.protection = False           # inline blocking enabled?
        self.default_policy = "allow"     # "allow" (Snort) | "deny" (firewall)
        self._home_net: list = []         # optional ip_network list
        self.traffic_sink = None          # optional per-packet feed (all packets)

        self._clock = threading.Lock()
        self.counters = {"packets": 0, "blocked": 0, "alerted": 0,
                         "passed": 0, "would_block": 0, "denied": 0}

    # --- configuration ----------------------------------------------------
    def reload_rules(self) -> None:
        with self._lock:
            self._store.reload()
            self._detector = Detector(self._store.rules)

    def reload_dpi(self) -> None:
        self._dpi.reload()

    def configure_scan(self, cfg: dict) -> None:
        self._scan.configure(**cfg)

    def set_protection(self, on: bool) -> None:
        self.protection = bool(on)

    def set_default_policy(self, policy: str) -> None:
        if policy in ("allow", "deny"):
            self.default_policy = policy

    def set_home_net(self, cidrs: list[str] | None) -> None:
        self._home_net = [ipaddress.ip_network(c, strict=False) for c in (cidrs or [])]

    def _in_home(self, rec: dict) -> bool:
        if not self._home_net:
            return True
        try:
            src = ipaddress.ip_address(rec["src_ip"])
            dst = ipaddress.ip_address(rec["dst_ip"])
        except ValueError:
            return False
        return any(src in n or dst in n for n in self._home_net)

    def _bump(self, key: str) -> None:
        with self._clock:
            self.counters[key] += 1

    def snapshot(self) -> dict:
        with self._clock:
            return dict(self.counters)

    # --- hot path ---------------------------------------------------------
    def process(self, rec: dict) -> bool:
        """Inspect one decoded packet. Return True to accept, False to drop."""
        self._bump("packets")
        if not self._in_home(rec):
            return True

        with self._lock:
            matched = self._detector.inspect(rec)
        findings = self._scan.inspect(rec) + self._dpi.inspect(rec)

        pass_rules = [r for r in matched if r.action == "pass"]
        drop_rules = [r for r in matched if r.action == "drop"]
        alert_rules = [r for r in matched if r.action in ("alert", "log")]
        drop_findings = [f for f in findings if f.action == "drop"]
        alert_findings = [f for f in findings if f.action != "drop"]

        accept = True
        verdict = "passed"
        blockers = drop_rules + drop_findings  # signatures + DPI that want a drop

        if pass_rules:
            pass                          # whitelisted — no security alerts
        elif blockers:
            if self.protection:
                accept, verdict = False, "blocked"
                self._bump("blocked")
            else:
                verdict = "would-block"
                self._bump("would_block")
            for b in blockers:
                self._alerter.fire(rec, b, verdict)
        elif self.default_policy == "deny":
            # Firewall-style allowlist: nothing explicitly passed this packet,
            # so deny it.
            if self.protection:
                accept, verdict = False, "default-deny"
                self._bump("denied")
                self._alerter.fire(rec, _DENY_FINDING, "default-deny")
            else:
                verdict = "would-block"
                self._bump("would_block")
                self._alerter.fire(rec, _DENY_FINDING, "would-block")

        if not pass_rules:
            for r in alert_rules:
                self._alerter.fire(rec, r, "alerted")
                self._bump("alerted")
            for f in alert_findings:
                self._alerter.fire(rec, f, "alerted")
                self._bump("alerted")
            if verdict == "passed" and (alert_rules or alert_findings):
                verdict = "alerted"       # accepted but flagged

        # "passed" is only meaningful once we are actively protecting: in monitor
        # mode every packet trivially passes, so we don't count those.
        if self.protection and verdict == "passed":
            self._bump("passed")

        if self.traffic_sink is not None:
            self.traffic_sink(build_traffic(rec, verdict))

        return accept
