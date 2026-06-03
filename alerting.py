"""Модуль 5 — вывод алертов. Собирает запись из (пакет, находка), глушит дубли и
раздаёт по приёмникам. Посредством pluggable-sinks (stdout, JSON Lines, web-Hub
pub/sub)."""

from __future__ import annotations
import collections
import json
import queue
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Protocol

import dissect

# A sink is just a function that consumes one alert record (a dict).
Sink = Callable[[dict], None]

# ANSI colours for terminal output
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_RESET  = "\033[0m"


class Finding(Protocol):
    """Anything with these attrs can raise an alert (Rule or analyzer.Finding)."""
    sid: int
    msg: str
    category: str
    action: str


def _payload_preview(payload: bytes, limit: int = 24) -> str:
    """Short printable/hex preview of the payload for the dashboard."""
    if not payload:
        return ""
    chunk = payload[:limit]
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    suffix = "…" if len(payload) > limit else ""
    return text + suffix


def build_record(pkt: dict, finding: Finding, verdict: str = "alerted") -> dict:
    """Flatten a matched (packet, finding) pair into a JSON-serialisable record.

    verdict is what actually happened to the packet: "blocked", "passed",
    "alerted" (allowed but flagged), or "would-block" (a drop rule matched but
    protection is off).
    """
    return {
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "sid": finding.sid,
        "msg": finding.msg,
        "category": getattr(finding, "category", "signature"),
        "action": getattr(finding, "action", "alert"),
        "verdict": verdict,
        "proto": pkt["proto"],
        "src_ip": pkt["src_ip"],
        "src_port": pkt["src_port"],
        "dst_ip": pkt["dst_ip"],
        "dst_port": pkt["dst_port"],
        "info": _payload_preview(pkt.get("payload", b"")),
        "interp": dissect.interpret(pkt),
        "hexdump": dissect.hexdump(pkt.get("payload", b"")),
        "flags": pkt.get("flags") or "",
        "len": pkt.get("len", 0),
    }


def build_traffic(pkt: dict, verdict: str) -> dict:
    """Compact per-packet record for the live traffic feed (every packet).

    Unlike alert records this carries no rule/sid — it is just "what crossed
    the wire and what the engine decided about it".
    """
    return {
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "verdict": verdict,
        "proto": pkt.get("proto") or "",
        "src_ip": pkt["src_ip"],
        "src_port": pkt.get("src_port"),
        "dst_ip": pkt["dst_ip"],
        "dst_port": pkt.get("dst_port"),
        "flags": pkt.get("flags") or "",
        "len": pkt.get("len", 0),
        "info": _payload_preview(pkt.get("payload", b"")),
        "interp": dissect.interpret(pkt),
        "hexdump": dissect.hexdump(pkt.get("payload", b"")),
    }


def stdout_sink(record: dict) -> None:
    src = f"{record['src_ip']}:{record['src_port']}" if record["src_port"] else record["src_ip"]
    dst = f"{record['dst_ip']}:{record['dst_port']}" if record["dst_port"] else record["dst_ip"]
    verdict = record.get("verdict", "alerted")
    tag = "BLOCKED" if verdict == "blocked" else verdict.upper()
    colour = _RED if verdict in ("blocked", "would-block") else _YELLOW
    print(
        f"{colour}[{tag}]{_RESET} {record['msg']}  "
        f"{record['proto'].upper()} {src} -> {dst}  "
        f"sid:{record['sid']}  {record['timestamp']}",
        file=sys.stderr,
    )


def make_jsonl_sink(path: str) -> Sink:
    """Return a sink that appends records as JSON Lines to *path*."""
    fh = open(path, "a", buffering=1)  # line-buffered

    def sink(record: dict) -> None:
        fh.write(json.dumps(record) + "\n")

    return sink


class Hub:
    """Tiny thread-safe pub/sub used to fan alerts out to web clients.

    Keeps a ring buffer of recent alerts so a browser that connects *after*
    the traffic happened (e.g. a finished pcap replay) still sees the backlog.
    """

    def __init__(self, history: int = 500) -> None:
        self._subscribers: list[queue.Queue] = []
        self._history: collections.deque = collections.deque(maxlen=history)
        self._lock = threading.Lock()

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=1000)
        with self._lock:
            backlog = list(self._history)
            self._subscribers.append(q)
        for record in backlog:  # replay history to the new client first
            try:
                q.put_nowait(record)
            except queue.Full:
                break
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def publish(self, record: dict) -> None:
        with self._lock:
            self._history.append(record)
            subscribers = list(self._subscribers)
        for q in subscribers:
            try:
                q.put_nowait(record)
            except queue.Full:
                pass  # slow client — drop rather than block the sniffer


class Alerter:
    """Builds alert records, suppresses duplicates, fans out to sinks.

    Throttling collapses repeats of the same (sid, src, dst) seen within
    *suppress_window* seconds into a single alert, so a busy flow or a noisy
    signature can't flood the console / dashboard.
    """

    def __init__(self, sinks: list[Sink], suppress_window: float = 5.0) -> None:
        self._sinks = sinks
        self._suppress_window = suppress_window
        self._last_seen: dict[tuple, float] = {}

    # Enforcement outcomes are audit-relevant: every dropped/would-drop packet
    # must be logged, so they bypass the dedup that tames noisy *alert* signatures.
    _ENFORCEMENT = ("blocked", "would-block", "default-deny")

    def _suppressed(self, record: dict) -> bool:
        if self._suppress_window <= 0:
            return False
        if record.get("verdict") in self._ENFORCEMENT:
            return False
        key = (record["sid"], record["src_ip"], record["dst_ip"])
        now = time.monotonic()
        last = self._last_seen.get(key)
        self._last_seen[key] = now
        return last is not None and now - last < self._suppress_window

    def fire(self, pkt: dict, finding: Finding, verdict: str = "alerted") -> None:
        record = build_record(pkt, finding, verdict)
        if self._suppressed(record):
            return
        for sink in self._sinks:
            sink(record)
