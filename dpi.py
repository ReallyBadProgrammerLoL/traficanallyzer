"""Глубокий разбор пакета (DPI) — ловит командную/эксфильтрационную активность и
блокирует её. Помечает трафик, который *ведёт себя* как туннель или C2, даже
когда конкретные байты меняются. Посредством эвристик по payload (а для DNS — по
qname / TXT) + конфигурируемых правил из dpi.json.

Что ищет:
  * shell / post-exploitation токены в payload
    (powershell, cmd.exe, certutil, base64 -d, /bin/sh, …);
  * длинные base64-подобные блобы в payload;
  * любой regex оператора по сырому payload (и для DNS — по qname / TXT);
  * для DNS отдельно: аномально длинные метки (классика туннелей/эксфильтрации).

Вся эвристика настраивается из дашборда (вкладка DPI) и хранится в dpi.json.
Срабатывание даёт drop-Finding, поэтому проходит тот же gate protection, что и
всё остальное: monitor -> "would-block", protect -> "blocked".
"""

from __future__ import annotations
import json
import os
import re
import sys
from dataclasses import dataclass, field

from analyzer import Finding
from dissect import parse_dns

_B64_RE = re.compile(rb"[A-Za-z0-9+/]{24,}={0,2}")  # long base64-ish run
_TARGETS = ("qname", "txt", "payload")
_BUILTIN_SID = 3001

# Defaults written to dpi.json on first run (and used if the file is unreadable).
DEFAULT_CONFIG: dict = {
    "enabled": True,
    "long_label": 40,           # bytes — longer single label = suspicious
    "base64_enabled": True,
    "tokens": [
        "powershell", "cmd.exe", "/bin/sh", "/bin/bash", "bash -i",
        "invoke-", "iex(", "iex ", " -enc", "-encodedcommand", "frombase64",
        "certutil", "bitsadmin", "mshta", "rundll32", "wget ", "curl ",
        "nc -", "ncat ", "whoami", "net user", "$(", "`", "&&", ";id",
    ],
    "patterns": [
        {"regex": r"(?i)union\s+select", "target": "payload",
         "msg": "SQL injection (UNION SELECT)", "sid": 3100},
        {"regex": r"\.\./\.\./", "target": "payload",
         "msg": "directory traversal (../../)", "sid": 3101},
        {"regex": r"/etc/(passwd|shadow)", "target": "payload",
         "msg": "sensitive file access (/etc/passwd)", "sid": 3102},
        {"regex": r"(?i)\b[0-9a-f]{32,}\b", "target": "qname",
         "msg": "long hex subdomain (DNS tunneling)", "sid": 3103},
    ],
}


@dataclass
class DPIPattern:
    regex: "re.Pattern"
    target: str
    msg: str
    sid: int


@dataclass
class DPIConfig:
    enabled: bool = True
    long_label: int = 40
    base64_enabled: bool = True
    tokens: list[bytes] = field(default_factory=list)        # lowercased bytes
    patterns: list[DPIPattern] = field(default_factory=list)


def _validate(data: dict) -> tuple[DPIConfig | None, list[str]]:
    """Validate a raw config dict; return (compiled config | None, errors)."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return None, ["config must be a JSON object"]

    long_label = data.get("long_label", 40)
    if not isinstance(long_label, int) or long_label < 1:
        errors.append("long_label must be a positive integer")

    raw_tokens = data.get("tokens", [])
    if not isinstance(raw_tokens, list):
        errors.append("tokens must be a list of strings")
        raw_tokens = []
    tokens = [t.lower().encode("latin-1") for t in raw_tokens
              if isinstance(t, str) and t]

    patterns: list[DPIPattern] = []
    raw_patterns = data.get("patterns", [])
    if not isinstance(raw_patterns, list):
        errors.append("patterns must be a list of objects")
        raw_patterns = []
    for i, p in enumerate(raw_patterns, 1):
        if not isinstance(p, dict):
            errors.append(f"pattern #{i}: must be an object")
            continue
        rx = p.get("regex", "")
        target = p.get("target", "qname")
        msg = p.get("msg", "")
        sid = p.get("sid")
        if not rx:
            errors.append(f"pattern #{i}: empty regex")
        if target not in _TARGETS:
            errors.append(f"pattern #{i}: target must be one of {_TARGETS}")
        if not msg:
            errors.append(f"pattern #{i}: empty msg")
        if not isinstance(sid, int):
            errors.append(f"pattern #{i}: sid must be an integer")
        try:
            compiled = re.compile(rx)
        except re.error as exc:
            errors.append(f"pattern #{i}: bad regex ({exc})")
            continue
        if rx and target in _TARGETS and msg and isinstance(sid, int):
            patterns.append(DPIPattern(compiled, target, msg, sid))

    if errors:
        return None, errors
    return DPIConfig(
        enabled=bool(data.get("enabled", True)),
        long_label=long_label,
        base64_enabled=bool(data.get("base64_enabled", True)),
        tokens=tokens,
        patterns=patterns,
    ), []


class DPIStore:
    """Loads / validates / persists the DPI heuristic configuration."""

    def __init__(self, path: str = "dpi.json") -> None:
        self.path = path
        self._raw: dict = dict(DEFAULT_CONFIG)
        self.config: DPIConfig = _validate(self._raw)[0]  # defaults are valid
        self.reload()

    def reload(self) -> None:
        if os.path.exists(self.path):
            try:
                with open(self.path) as fh:
                    data = json.load(fh)
                cfg, errors = _validate(data)
                if cfg is not None:
                    self._raw, self.config = data, cfg
                    return
                print(f"[!] dpi: {self.path} invalid ({'; '.join(errors)}); "
                      "using defaults", file=sys.stderr)
            except (OSError, ValueError) as exc:
                print(f"[!] dpi: cannot read {self.path} ({exc}); using defaults",
                      file=sys.stderr)
            self._raw = dict(DEFAULT_CONFIG)
            self.config = _validate(self._raw)[0]
        else:
            self._raw = dict(DEFAULT_CONFIG)
            self.config = _validate(self._raw)[0]
            self._write(self._raw)

    def raw(self) -> dict:
        return json.loads(json.dumps(self._raw))  # deep copy for the API

    def save(self, data: dict) -> list[str]:
        """Validate + persist; return [] on success or a list of errors."""
        cfg, errors = _validate(data)
        if errors:
            return errors
        self._write(data)
        self._raw, self.config = data, cfg
        return []

    def _write(self, data: dict) -> None:
        with open(self.path, "w") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)


def _is_dns(rec: dict) -> bool:
    return rec.get("proto") in ("udp", "tcp") and 53 in (
        rec.get("src_port"), rec.get("dst_port"))


class DPIInspector:
    def __init__(self, store: DPIStore | None = None) -> None:
        self._store = store or DPIStore()

    @property
    def cfg(self) -> DPIConfig:
        return self._store.config

    def reload(self) -> None:
        self._store.reload()

    def inspect(self, rec: dict) -> list[Finding]:
        cfg = self.cfg
        if not cfg.enabled:
            return []
        payload = rec.get("payload") or b""
        if not payload:
            return []

        findings: list[Finding] = []
        reasons: list[str] = []

        # --- protocol-agnostic checks: run on every packet's payload ----------
        low = payload.lower()
        for tok in cfg.tokens:
            if tok in low:
                reasons.append(f"command token '{tok.decode('latin-1').strip()}'")
        if cfg.base64_enabled and _B64_RE.search(payload):
            reasons.append("base64 blob in payload")

        # --- DNS-specific structural heuristic (tunneling via long labels) ----
        dns = parse_dns(payload) if _is_dns(rec) else None
        if dns:
            for label in dns["labels"]:
                if len(label) > cfg.long_label:
                    reasons.append(f"oversized DNS label ({len(label)}B — tunneling)")

        if reasons:
            seen, uniq = set(), []
            for r in reasons:
                if r not in seen:
                    seen.add(r)
                    uniq.append(r)
            findings.append(Finding(
                sid=_BUILTIN_SID,
                msg="DPI: " + "; ".join(uniq[:3]),
                category="dpi",
                action="drop",
            ))

        if cfg.patterns:
            qname = dns["qname"] if dns else ""
            txts = dns["txt"] if dns else []
            ptext = payload.decode("latin-1")
            for pat in cfg.patterns:
                if pat.target == "qname":
                    hit = bool(qname) and pat.regex.search(qname)
                elif pat.target == "txt":
                    hit = any(pat.regex.search(t) for t in txts)
                else:  # payload — any protocol
                    hit = pat.regex.search(ptext)
                if hit:
                    findings.append(Finding(
                        sid=pat.sid,
                        msg="DPI: " + pat.msg,
                        category="dpi",
                        action="drop",
                    ))
        return findings
