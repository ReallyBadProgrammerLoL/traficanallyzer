"""Управление правилами iptables для inline-режима (IPS). Заворачивает трафик
интерфейса в NFQUEUE на время protection и снимает правила при
выключении/выходе. Посредством iptables -I/-D … -j NFQUEUE --queue-bypass.

Правила ставятся только когда оператор включает protection, и всегда с
--queue-bypass — если наш процесс умрёт, ядро откроет проход (fail-open, трафик
продолжит идти), а не заблокирует сеть. Каждое добавленное правило отслеживается
и снимается при disable / выходе процесса.
"""

from __future__ import annotations
import atexit
import subprocess
import sys


class Firewall:
    def __init__(self, queue_num: int = 1) -> None:
        self.queue_num = queue_num
        self._active: list[list[str]] = []  # rule specs we inserted
        atexit.register(self.clear)

    def _spec(self, chain: str, iface: str) -> list[str]:
        flag = "-i" if chain == "INPUT" else "-o"
        return [chain, flag, iface, "-j", "NFQUEUE",
                "--queue-num", str(self.queue_num), "--queue-bypass"]

    @staticmethod
    def _run(args: list[str]) -> tuple[int, str]:
        proc = subprocess.run(["iptables", *args],
                              capture_output=True, text=True)
        return proc.returncode, (proc.stderr or proc.stdout).strip()

    def enable(self, iface: str) -> None:
        """Insert NFQUEUE rules for *iface* on both directions (idempotent)."""
        for chain in ("INPUT", "OUTPUT"):
            spec = self._spec(chain, iface)
            self._run(["-D", *spec])           # drop any stale duplicate first
            rc, err = self._run(["-I", *spec])
            if rc != 0:
                self.clear()
                raise RuntimeError(f"iptables -I {chain} failed: {err}")
            self._active.append(spec)
        print(f"[*] firewall: NFQUEUE {self.queue_num} active on {iface}",
              file=sys.stderr)

    def clear(self) -> None:
        """Remove every rule we added."""
        for spec in self._active:
            self._run(["-D", *spec])
        if self._active:
            print("[*] firewall: rules cleared", file=sys.stderr)
        self._active = []
