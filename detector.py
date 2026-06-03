"""Модуль 4 — сигнатурный осмотр. Сопоставляет пакет с правилами: пре-фильтр по
заголовку + поиск контента в payload. Посредством одного автомата Aho-Corasick
(pyahocorasick).

Почему Aho-Corasick, а не наивный цикл:
  Наивно — перебрать все правила и для каждого `content in payload`, то есть
  O(R * P) на пакет (R = правил, P = длина payload). Aho-Corasick компилирует
  все content-паттерны в один автомат на старте и сканирует payload за один
  проход O(P), сразу сообщая *все* совпавшие паттерны. Стоимость на пакет
  перестаёт зависеть от числа сигнатур — это и позволяет набору правил расти.

Работа с байтами:
  Automaton из pyahocorasick работает со строками, а payload — это сырые байты.
  Маппим байты <-> str через latin-1 (1:1 для всех 256 значений), так что
  автомат фактически работает по байтам.
"""

from __future__ import annotations
from rule_parser import Rule

try:
    import ahocorasick
    _AC_AVAILABLE = True
except ImportError:
    _AC_AVAILABLE = False
    print("[!] detector: pyahocorasick not found — falling back to linear search")
    print("    Install with: pip install pyahocorasick")


class Detector:
    def __init__(self, rules: list[Rule]) -> None:
        self._rules = rules
        self._ac = None
        self._content_patterns: set[bytes] = {
            r.content for r in rules if r.content is not None
        }
        self._build_automaton()

    def _build_automaton(self) -> None:
        if not _AC_AVAILABLE or not self._content_patterns:
            return
        A = ahocorasick.Automaton()
        for pattern in self._content_patterns:
            A.add_word(pattern.decode("latin-1"), pattern)  # key=str, value=bytes
        A.make_automaton()
        self._ac = A

    def _scan_content(self, payload: bytes) -> set[bytes]:
        """Return the set of content patterns present in *payload* (one pass)."""
        if not payload:
            return set()
        if self._ac is not None:
            hay = payload.decode("latin-1")
            return {value for _, value in self._ac.iter(hay)}
        # Linear fallback
        return {p for p in self._content_patterns if p in payload}

    def inspect(self, pkt: dict) -> list[Rule]:
        """Return the list of rules that match *pkt*."""
        # One Aho-Corasick pass over the payload finds all content matches.
        present = self._scan_content(pkt["payload"])

        matched: list[Rule] = []
        for rule in self._rules:
            if not rule.match_header(pkt):
                continue
            if rule.content is not None and rule.content not in present:
                continue
            if rule.flags and pkt.get("flags") and rule.flags not in pkt["flags"]:
                continue
            matched.append(rule)
        return matched
