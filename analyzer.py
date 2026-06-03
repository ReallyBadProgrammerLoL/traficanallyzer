"""Стейтфул-анализ — детект сканов/свипов + correlation-автоблок. Ловит то, что
видно только *между* пакетами: скан портов одного хоста, свип многих хостов,
флуд «пустых» SYN. Посредством скользящего окна попыток подключения по каждому
src-IP.

Сигнатурные правила (detector.py) стейтлесс — смотрят один пакет за раз. Скан же
виден лишь в совокупности: один SYN нормален, а один источник по многим
портам/хостам за пару секунд — атака. Модуль поднимает *один* алерт на скан (а не
на каждый SYN); это та же идея, что `detection_filter` / flow-tracking в Suricata,
сознательно упрощённая.

Поверх детекта — *корреляция*: пересёкший порог скана/свипа/флуда источник
уходит в короткий «карантин», и каждый его следующий пакет (не только SYN)
получает drop-Finding — то есть сканер шунится на время, а не просто логируется.
Как и любой drop, вердикт гейтится режимом: protect -> blocked,
monitor -> would-block.
"""

from __future__ import annotations
import json
import os
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass

# Tunable thresholds, persisted to scan.json and editable from the dashboard.
SCAN_DEFAULTS: dict = {
    "window": 5.0,                 # sliding-window seconds
    "port_scan_threshold": 10,     # distinct ports on one host -> port scan
    "sweep_threshold": 10,         # distinct hosts -> host sweep
    "flood_threshold": 20,         # total bare SYNs -> probe flood
    "cooldown": 15.0,              # seconds between repeat alerts per source
    "block": True,                 # quarantine (auto-block) offenders
    "block_duration": 30.0,        # seconds an offender stays shunned
}


@dataclass
class Finding:
    """A stateful detection result, shaped like a Rule for the alerter."""
    sid: int
    msg: str
    category: str
    action: str = "alert"


class ScanDetector:
    def __init__(
        self,
        window: float = 5.0,
        port_scan_threshold: int = 10,
        sweep_threshold: int = 10,
        cooldown: float = 15.0,
        block: bool = True,
        flood_threshold: int = 20,
        block_duration: float = 30.0,
    ) -> None:
        self._window = window
        self._port_thr = port_scan_threshold
        self._sweep_thr = sweep_threshold
        self._cooldown = cooldown
        self._block = block
        self._flood_thr = flood_threshold      # total bare-SYN probes -> quarantine
        self._block_duration = block_duration
        # src_ip -> deque[(ts, dst_ip, dst_port)]
        self._events: dict[str, deque] = defaultdict(deque)
        # (src_ip, kind) -> last_alert_ts, to avoid re-alerting every packet
        self._last_alert: dict[tuple, float] = {}
        # src_ip -> quarantine expiry ts; while active, all traffic is dropped
        self._quarantine: dict[str, float] = {}

    def configure(self, *, window=None, port_scan_threshold=None,
                  sweep_threshold=None, flood_threshold=None, cooldown=None,
                  block=None, block_duration=None) -> None:
        """Apply new thresholds live (existing window/quarantine state is kept)."""
        if window is not None:              self._window = window
        if port_scan_threshold is not None: self._port_thr = port_scan_threshold
        if sweep_threshold is not None:    self._sweep_thr = sweep_threshold
        if flood_threshold is not None:    self._flood_thr = flood_threshold
        if cooldown is not None:           self._cooldown = cooldown
        if block is not None:              self._block = block
        if block_duration is not None:     self._block_duration = block_duration

    def _is_probe(self, pkt: dict) -> bool:
        """A connection attempt worth counting toward a scan."""
        if pkt["proto"] == "icmp":
            return True  # echo requests count toward a ping sweep
        if pkt["proto"] == "tcp":
            flags = pkt.get("flags") or ""
            return "S" in flags and "A" not in flags  # bare SYN
        return False

    def _cooled_down(self, key: tuple, now: float) -> bool:
        last = self._last_alert.get(key)
        if last is not None and now - last < self._cooldown:
            return False
        self._last_alert[key] = now
        return True

    def inspect(self, pkt: dict) -> list[Finding]:
        now = time.monotonic()
        src = pkt["src_ip"]

        # --- correlation gate: a quarantined source is shunned wholesale -------
        if self._block:
            expiry = self._quarantine.get(src)
            if expiry is not None:
                if now < expiry:
                    return [Finding(
                        sid=2003,
                        msg=f"Quarantined scanner {src} "
                            f"(auto-block {self._block_duration:.0f}s)",
                        category="scan-block",
                        action="drop",
                    )]
                del self._quarantine[src]   # expired — give the source a fresh start

        if not self._is_probe(pkt):
            return []

        events = self._events[src]
        events.append((now, pkt["dst_ip"], pkt["dst_port"]))

        # Drop events older than the window.
        cutoff = now - self._window
        while events and events[0][0] < cutoff:
            events.popleft()

        distinct_hosts = {dst_ip for _, dst_ip, _ in events}
        # Ports targeted on the single most-hit host (classic port scan).
        ports_per_host: dict[str, set] = defaultdict(set)
        for _, dst_ip, dst_port in events:
            if dst_port is not None:
                ports_per_host[dst_ip].add(dst_port)

        findings: list[Finding] = []
        tripped = False        # did any threshold fire this packet?

        if len(distinct_hosts) >= self._sweep_thr and self._cooled_down((src, "sweep"), now):
            tripped = True
            findings.append(Finding(
                sid=2001,
                msg=f"Host sweep: {src} probed {len(distinct_hosts)} hosts "
                    f"in {self._window:.0f}s",
                category="sweep",
            ))

        for dst_ip, ports in ports_per_host.items():
            if len(ports) >= self._port_thr and self._cooled_down((src, dst_ip, "portscan"), now):
                tripped = True
                findings.append(Finding(
                    sid=2002,
                    msg=f"Port scan: {src} hit {len(ports)} ports on {dst_ip} "
                        f"in {self._window:.0f}s",
                    category="portscan",
                ))

        # Sheer volume of bare SYNs from one source, regardless of fan-out.
        if len(events) >= self._flood_thr and self._cooled_down((src, "flood"), now):
            tripped = True
            findings.append(Finding(
                sid=2004,
                msg=f"Probe flood: {src} sent {len(events)} bare SYNs "
                    f"in {self._window:.0f}s",
                category="flood",
            ))

        # Correlation: any tripped threshold quarantines the source so every
        # subsequent packet (handled at the top of inspect) is dropped.
        if self._block and tripped:
            self._quarantine[src] = now + self._block_duration

        return findings


_INT_KEYS = ("port_scan_threshold", "sweep_threshold", "flood_threshold")
_NUM_KEYS = ("window", "cooldown", "block_duration")


def _validate_scan(data: dict) -> tuple[dict | None, list[str]]:
    """Validate a raw scan-config dict; return (clean config | None, errors)."""
    if not isinstance(data, dict):
        return None, ["config must be a JSON object"]
    errors: list[str] = []
    cfg = dict(SCAN_DEFAULTS)

    for k in _INT_KEYS:
        v = data.get(k, SCAN_DEFAULTS[k])
        if not isinstance(v, int) or isinstance(v, bool) or v < 1:
            errors.append(f"{k} must be a positive integer")
        else:
            cfg[k] = v
    for k in _NUM_KEYS:
        v = data.get(k, SCAN_DEFAULTS[k])
        if isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0:
            errors.append(f"{k} must be a non-negative number")
        else:
            cfg[k] = float(v)
    cfg["block"] = bool(data.get("block", True))

    if errors:
        return None, errors
    return cfg, []


class ScanStore:
    """Loads / validates / persists the scan-detector thresholds (scan.json)."""

    def __init__(self, path: str = "scan.json") -> None:
        self.path = path
        self.config: dict = dict(SCAN_DEFAULTS)
        self.reload()

    def reload(self) -> None:
        if os.path.exists(self.path):
            try:
                with open(self.path) as fh:
                    data = json.load(fh)
                cfg, errors = _validate_scan(data)
                if cfg is not None:
                    self.config = cfg
                    return
                print(f"[!] scan: {self.path} invalid ({'; '.join(errors)}); "
                      "using defaults", file=sys.stderr)
            except (OSError, ValueError) as exc:
                print(f"[!] scan: cannot read {self.path} ({exc}); using defaults",
                      file=sys.stderr)
            self.config = dict(SCAN_DEFAULTS)
        else:
            self.config = dict(SCAN_DEFAULTS)
            self._write(self.config)

    def raw(self) -> dict:
        return dict(self.config)

    def save(self, data: dict) -> list[str]:
        cfg, errors = _validate_scan(data)
        if errors:
            return errors
        self._write(cfg)
        self.config = cfg
        return []

    def _write(self, data: dict) -> None:
        with open(self.path, "w") as fh:
            json.dump(data, fh, indent=2)
