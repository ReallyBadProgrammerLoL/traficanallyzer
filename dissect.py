"""Разбор содержимого пакета — hex-дамп + лёгкое декодирование протоколов
(DNS / HTTP). Слой «заглянуть внутрь пакета» для детального вида дашборда и
DPI-модуля. Посредством работы напрямую с сырыми байтами payload (без Scapy в
рантайме).
"""

from __future__ import annotations

_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
           16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}


def hexdump(payload: bytes, limit: int = 256) -> str:
    """Classic offset / hex / ASCII dump, capped at *limit* bytes."""
    if not payload:
        return ""
    chunk = payload[:limit]
    lines = []
    for off in range(0, len(chunk), 16):
        row = chunk[off:off + 16]
        hex_part = " ".join(f"{b:02x}" for b in row)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{off:04x}  {hex_part:<47}  {asc}")
    if len(payload) > limit:
        lines.append(f"....  ... (+{len(payload) - limit} more bytes)")
    return "\n".join(lines)


def _read_name(data: bytes, off: int, _depth: int = 0):
    """Read a DNS name (with compression pointers). Returns (labels, next_off)."""
    labels: list[bytes] = []
    while off < len(data) and _depth < 16:
        length = data[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if off + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            sub, _ = _read_name(data, ptr, _depth + 1)
            labels.extend(sub)
            off += 2
            return labels, off
        off += 1
        labels.append(data[off:off + length])
        off += length
    return labels, off


def parse_dns(payload: bytes) -> dict | None:
    """Best-effort DNS parse. Returns labels of the qname and any TXT strings."""
    if len(payload) < 12:
        return None
    flags = int.from_bytes(payload[2:4], "big")
    qd = int.from_bytes(payload[4:6], "big")
    an = int.from_bytes(payload[6:8], "big")
    out = {"is_response": bool(flags & 0x8000), "qdcount": qd, "ancount": an,
           "qname": "", "qtype": None, "labels": [], "txt": []}
    off = 12
    try:
        for i in range(qd):
            labels, off = _read_name(payload, off)
            qtype = int.from_bytes(payload[off:off + 2], "big")
            off += 4  # qtype(2) + qclass(2)
            if i == 0:
                out["labels"] = labels
                out["qname"] = ".".join(l.decode("latin-1") for l in labels)
                out["qtype"] = qtype
        for _ in range(an):
            _, off = _read_name(payload, off)
            rtype = int.from_bytes(payload[off:off + 2], "big")
            off += 8  # type(2) class(2) ttl(4)
            rdlen = int.from_bytes(payload[off:off + 2], "big")
            off += 2
            rdata = payload[off:off + rdlen]
            off += rdlen
            if rtype == 16:  # TXT: one or more length-prefixed strings
                j = 0
                while j < len(rdata):
                    sl = rdata[j]
                    j += 1
                    out["txt"].append(rdata[j:j + sl].decode("latin-1"))
                    j += sl
    except (IndexError, ValueError):
        pass
    return out


def interpret(rec: dict) -> str:
    """One-line human-readable summary of what the payload *is*."""
    proto = rec.get("proto")
    payload = rec.get("payload") or b""
    sport, dport = rec.get("src_port"), rec.get("dst_port")

    if proto in ("udp", "tcp") and 53 in (sport, dport):
        dns = parse_dns(payload)
        if dns:
            kind = "response" if dns["is_response"] else "query"
            qt = _QTYPES.get(dns["qtype"], str(dns["qtype"]))
            line = f"DNS {kind}: {dns['qname'] or '?'} [{qt}]"
            if dns["txt"]:
                line += "  TXT=" + " | ".join(dns["txt"])
            return line

    if proto == "tcp" and (80 in (sport, dport) or 8080 in (sport, dport)):
        head = payload[:80].decode("latin-1", "replace")
        first = head.split("\r\n", 1)[0].strip()
        if first:
            return f"HTTP: {first}"

    if not payload:
        return "(no payload)"
    preview = "".join(chr(b) if 32 <= b < 127 else "." for b in payload[:48])
    return f"raw: {preview}"
