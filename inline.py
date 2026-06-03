"""Inline-путь IPS — читает пакеты из NFQUEUE и выносит accept/drop по решению
движка. Посредством netfilterqueue + разбора пакета Scapy.

В отличие от пассивного сниффинга, сидит в forwarding-пути ядра: возвращаемый
вердикт реально решает судьбу пакета — именно это и даёт блокировку.
"""

from __future__ import annotations
import socket
import sys
import threading

from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP

import decoder
from engine import Engine


class InlineIPS:
    def __init__(self, engine: Engine, queue_num: int = 1) -> None:
        self._engine = engine
        self._queue_num = queue_num
        self._nfq: NetfilterQueue | None = None
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = threading.Event()

    def _callback(self, nfq_pkt) -> None:
        try:
            scapy_pkt = IP(nfq_pkt.get_payload())
            rec = decoder.decode(scapy_pkt)
            accept = True if rec is None else self._engine.process(rec)
        except Exception as exc:  # never let one bad packet wedge the queue
            print(f"[!] inline: {exc}", file=sys.stderr)
            accept = True
        if accept:
            nfq_pkt.accept()
        else:
            nfq_pkt.drop()

    def start(self) -> None:
        if self._running.is_set():
            return
        self._nfq = NetfilterQueue()
        self._nfq.bind(self._queue_num, self._callback)
        self._sock = socket.fromfd(self._nfq.get_fd(),
                                   socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.settimeout(1.0)
        self._running.set()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="inline-ips")
        self._thread.start()

    def _loop(self) -> None:
        while self._running.is_set():
            try:
                self._nfq.run_socket(self._sock)
            except socket.timeout:
                continue
            except OSError:
                break
        try:
            self._nfq.unbind()
        except Exception:
            pass

    def stop(self) -> None:
        self._running.clear()
        if self._thread:
            self._thread.join(timeout=3)
        if self._sock:
            self._sock.close()
        self._nfq = self._sock = self._thread = None
