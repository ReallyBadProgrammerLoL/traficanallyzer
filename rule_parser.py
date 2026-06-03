"""Модуль 3 — правила. Разбирает Snort-синтаксис в объекты Rule и держит их в
редактируемом RuleStore. Посредством регулярных выражений + валидации.

Действия Snort → три категории оператора:
    drop   -> blocked   (пакет дропается, inline/IPS-режим)
    alert  -> alerted   (пропускается, но флагается оператору)
    pass   -> passed    (явный whitelist, без алерта)
"""

from __future__ import annotations
import re
from dataclasses import dataclass

ACTIONS = ("drop", "alert", "log", "pass")

_HEADER_RE = re.compile(
    r"^(drop|alert|log|pass)\s+"       # action
    r"(\w+)\s+"                        # proto
    r"(\S+)\s+(\S+)\s+"               # src_ip  src_port
    r"(->|<>)\s+"                      # direction
    r"(\S+)\s+(\S+)\s*"               # dst_ip  dst_port
    r"\((.+)\)$",                      # options block
    re.DOTALL,
)

_OPT_RE = re.compile(r'(\w+)\s*:\s*"([^"]*)"')  # key:"value" pairs
_HEX_RE = re.compile(r"\|([0-9a-fA-F ]+)\|")


def _parse_port(s: str) -> int | None:
    return None if s == "any" else int(s)


def _hex_to_bytes(match: re.Match) -> bytes:
    return bytes(int(b, 16) for b in match.group(1).split())


def _parse_content(raw: str) -> bytes:
    """Convert a content string (possibly with |xx xx| hex escapes) to bytes."""
    parts: list[bytes] = []
    last = 0
    for m in _HEX_RE.finditer(raw):
        parts.append(raw[last:m.start()].encode())
        parts.append(_hex_to_bytes(m))
        last = m.end()
    parts.append(raw[last:].encode())
    return b"".join(parts)


@dataclass
class Rule:
    action: str
    proto: str
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    msg: str
    content: bytes | None
    flags: str | None
    sid: int
    category: str = "signature"
    raw: str = ""

    def match_header(self, pkt: dict) -> bool:
        """Quick proto/port/IP pre-filter before payload search."""
        if self.proto != "any" and pkt["proto"] != self.proto:
            return False
        if self.dst_port is not None and pkt["dst_port"] != self.dst_port:
            return False
        if self.src_port is not None and pkt["src_port"] != self.src_port:
            return False
        if self.src_ip != "any" and pkt["src_ip"] != self.src_ip:
            return False
        if self.dst_ip != "any" and pkt["dst_ip"] != self.dst_ip:
            return False
        return True


def parse_line(line: str, lineno: int = 0) -> Rule | None:
    """Parse a single rule line; return None for blank/comment/invalid."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = _HEADER_RE.match(line)
    if not m:
        return None

    action, proto, src_ip, src_port_s, _dir, dst_ip, dst_port_s, opts = m.groups()
    options = dict(_OPT_RE.findall(opts))
    sid_m = re.search(r"sid:(\d+)", opts)
    flags_m = re.search(r"flags:(\w+)", opts)

    return Rule(
        action=action,
        proto=proto,
        src_ip=src_ip,
        src_port=_parse_port(src_port_s),
        dst_ip=dst_ip,
        dst_port=_parse_port(dst_port_s),
        msg=options.get("msg", ""),
        content=_parse_content(options["content"]) if "content" in options else None,
        flags=flags_m.group(1) if flags_m else None,
        sid=int(sid_m.group(1)) if sid_m else lineno,
        raw=line,
    )


def load(path: str) -> list[Rule]:
    rules: list[Rule] = []
    with open(path) as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            rule = parse_line(line, lineno)
            if rule is None:
                print(f"[!] rule_parser: skipping unparseable line {lineno}")
                continue
            rules.append(rule)
    print(f"[*] rule_parser: loaded {len(rules)} rules from {path}")
    return rules


class RuleStore:
    """Holds the rules file as editable text and exposes parsed Rule objects."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.rules: list[Rule] = []
        self.reload()

    def reload(self) -> None:
        self.rules = load(self.path)

    def text(self) -> str:
        with open(self.path) as fh:
            return fh.read()

    def validate(self, text: str) -> list[str]:
        """Return a list of error strings for unparseable, non-comment lines."""
        errors = []
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if parse_line(line, i) is None:
                errors.append(f"line {i}: {s}")
        return errors

    def save_text(self, text: str) -> list[str]:
        """Validate and persist new rules text; reload on success.

        Returns a list of errors; if non-empty, nothing is written.
        """
        errors = self.validate(text)
        if errors:
            return errors
        with open(self.path, "w") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
        self.reload()
        return []
