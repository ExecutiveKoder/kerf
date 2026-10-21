"""
Reconstructed views over captured proxy flows.

This is application-layer capture (what Kerf already saw), not a promiscuous
NIC sniff. List, header tree, hex, filter, follow-conversation, and
pcap export apply to HTTP/S that went through the proxy.
"""

from __future__ import annotations

import hashlib
import io
import re
import struct
from urllib.parse import urlsplit


# --------------------------------------------------------------------------- #
# View filter
# --------------------------------------------------------------------------- #

_TOKEN = re.compile(
    r"""\s*(?:
        (?P<and>&&|\band\b) |
        (?P<or>\|\||\bor\b) |
        (?P<not>!|\bnot\b) |
        (?P<op>==|!=|>=|<=|>|<|\bcontains\b|\beq\b) |
        (?P<lp>\() | (?P<rp>\)) |
        (?P<str>"[^"]*"|'[^']*') |
        (?P<num>\d+) |
        (?P<id>[A-Za-z_][\w.]*)
    )""",
    re.I | re.X,
)


def _tokenize(expr: str) -> list:
    out = []
    pos = 0
    for m in _TOKEN.finditer(expr):
        if m.start() != pos and expr[pos:m.start()].strip():
            raise ValueError(f"bad filter near: {expr[pos:m.start()]!r}")
        pos = m.end()
        kind = m.lastgroup
        val = m.group(kind)
        if kind == "str":
            out.append(("str", val[1:-1]))
        elif kind == "num":
            out.append(("num", int(val)))
        elif kind == "id":
            out.append(("id", val.lower()))
        else:
            out.append((kind, val.lower().strip()))
    if pos < len(expr) and expr[pos:].strip():
        raise ValueError(f"bad filter near: {expr[pos:]!r}")
    return out


class _Parser:
    def __init__(self, tokens):
        self.toks = tokens
        self.i = 0

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else (None, None)

    def take(self, *kinds):
        kind, val = self.peek()
        if kind not in kinds:
            return None
        self.i += 1
        return kind, val

    def parse(self):
        if not self.toks:
            return None
        node = self._or()
        if self.i < len(self.toks):
            raise ValueError("unexpected extra tokens")
        return node

    def _or(self):
        left = self._and()
        while self.take("or"):
            left = ("or", left, self._and())
        return left

    def _and(self):
        left = self._not()
        while self.take("and"):
            left = ("and", left, self._not())
        return left

    def _not(self):
        if self.take("not"):
            return ("not", self._not())
        return self._prim()

    def _prim(self):
        if self.take("lp"):
            node = self._or()
            if not self.take("rp"):
                raise ValueError("missing )")
            return node
        kind, val = self.take("id") or (None, None)
        if not kind:
            raise ValueError("expected field")
        op = self.take("op")
        if not op:
            return ("exists", val)
        rhs = self.take("str", "num", "id")
        if not rhs:
            raise ValueError("expected value after operator")
        return ("cmp", val, op[1], rhs[1])


def parse_filter(expr: str):
    expr = (expr or "").strip()
    if not expr:
        return None
    return _Parser(_tokenize(expr)).parse()


def _field(pkt: dict, name: str):
    name = name.lower()
    aliases = {
        "http.method": pkt.get("method"),
        "http.host": pkt.get("host"),
        "http.path": pkt.get("path"),
        "http.url": pkt.get("url"),
        "http.status": pkt.get("status"),
        "http.content_type": pkt.get("mime"),
        "http.request": True,
        "http.response": bool(pkt.get("status")),
        "http": True,
        "tls": "http/2" in (pkt.get("protocol") or "") or (pkt.get("url") or "").startswith("https"),
        "http2": "http/2" in (pkt.get("protocol") or "").lower() or pkt.get("protocol") == "h2",
        "websocket": (pkt.get("protocol") or "") == "websocket",
        "frame.len": pkt.get("length") or 0,
        "tcp.len": pkt.get("length") or 0,
        "ip.host": pkt.get("host"),
        "ip.addr": pkt.get("host"),
        "ip.src": pkt.get("src"),
        "ip.dst": pkt.get("dst"),
        "ip.dst_host": pkt.get("host"),
        "tcp": True,
    }
    return aliases.get(name, pkt.get(name))


def _eval(node, pkt) -> bool:
    if node is None:
        return True
    op = node[0]
    if op == "exists":
        name = node[1]
        if name in ("http", "tcp", "http.request"):
            return True
        val = _field(pkt, name)
        return bool(val)
    if op == "not":
        return not _eval(node[1], pkt)
    if op == "and":
        return _eval(node[1], pkt) and _eval(node[2], pkt)
    if op == "or":
        return _eval(node[1], pkt) or _eval(node[2], pkt)
    if op == "cmp":
        field, oper, rhs = node[1], node[2], node[3]
        if field == "tcp" and oper in ("contains",):
            blob = ((pkt.get("req_raw") or "") + (pkt.get("resp_raw") or "")).lower()
            return str(rhs).lower() in blob
        left = _field(pkt, field)
        if oper == "contains":
            return str(rhs).lower() in str(left or "").lower()
        if oper in ("==", "eq"):
            if isinstance(left, int) or isinstance(rhs, int):
                try:
                    return int(left or 0) == int(rhs)
                except (TypeError, ValueError):
                    return str(left) == str(rhs)
            return str(left or "").lower() == str(rhs).lower()
        if oper == "!=":
            return not _eval(("cmp", field, "==", rhs), pkt)
        try:
            lv, rv = float(left or 0), float(rhs)
        except (TypeError, ValueError):
            return False
        if oper == ">":
            return lv > rv
        if oper == "<":
            return lv < rv
        if oper == ">=":
            return lv >= rv
        if oper == "<=":
            return lv <= rv
    return False


def match_filter(expr: str, pkt: dict) -> bool:
    try:
        return _eval(parse_filter(expr), pkt)
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# Packet shaping + dissection
# --------------------------------------------------------------------------- #

def _host_ip(host: str) -> str:
    host = (host or "0.0.0.0").split(":")[0]
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        return host
    h = hashlib.md5(host.encode()).digest()
    return f"10.{h[0]}.{h[1]}.{h[2]}"


def as_packet(row: dict, *, no: int, t0: float) -> dict:
    proto = (row.get("protocol") or "http/1.1").lower()
    if proto in ("h2", "http/2"):
        protocol = "HTTP2"
    elif proto == "websocket":
        protocol = "WebSocket"
    elif (row.get("url") or "").startswith("https"):
        protocol = "TLSv1.2"
    else:
        protocol = "HTTP"
    info = f"{row.get('method') or ''} {row.get('path') or '/'}"
    if row.get("status"):
        info += f" → {row['status']}"
    return {
        "no": no,
        "id": row.get("id"),
        "time": round((row.get("timestamp") or t0) - t0, 6),
        "timestamp": row.get("timestamp"),
        "src": "127.0.0.1",
        "dst": _host_ip(row.get("host") or ""),
        "host": row.get("host") or "",
        "protocol": protocol,
        "wire_protocol": row.get("protocol") or "",
        "length": int(row.get("req_length") or 0) + int(row.get("resp_length") or 0),
        "info": info.strip(),
        "method": row.get("method") or "",
        "path": row.get("path") or "",
        "url": row.get("url") or "",
        "status": row.get("status"),
        "mime": row.get("mime") or "",
        "duration_ms": row.get("duration_ms"),
        "color": _color(row, protocol),
    }


def _color(row, protocol) -> str:
    st = row.get("status") or 0
    if protocol == "WebSocket":
        return "ws"
    if st >= 500:
        return "s5"
    if st >= 400:
        return "s4"
    if st >= 300:
        return "s3"
    if protocol == "HTTP2":
        return "h2"
    if protocol.startswith("TLS"):
        return "tls"
    return "s2"


def _split_http(raw: str):
    raw = (raw or "").replace("\r\n", "\n")
    head, _, body = raw.partition("\n\n")
    lines = head.split("\n")
    headers = []
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers.append((k.strip(), v.strip()))
    return lines[0] if lines else "", headers, body


def dissect(row: dict) -> list:
    """Protocol tree nodes: {name, value, children, start, end} offsets into combined bytes."""
    req = row.get("req_raw") or ""
    resp = row.get("resp_raw") or ""
    tree = []
    frame_len = len(req.encode("latin-1")) + len(resp.encode("latin-1"))
    tree.append({
        "name": "Frame",
        "value": f"{frame_len} bytes on wire (reconstructed)",
        "children": [
            {"name": "Arrival Time", "value": str(row.get("timestamp") or "")},
            {"name": "Frame Number", "value": str(row.get("id") or "")},
            {"name": "Frame Length", "value": str(frame_len)},
            {"name": "Protocols in frame", "value": "eth:ip:tcp:http"},
        ],
    })
    tree.append({
        "name": "Internet Protocol Version 4",
        "value": f"127.0.0.1 → {_host_ip(row.get('host') or '')}",
        "children": [
            {"name": "Source", "value": "127.0.0.1"},
            {"name": "Destination", "value": _host_ip(row.get("host") or "")},
            {"name": "Destination Host", "value": row.get("host") or ""},
        ],
    })
    tree.append({
        "name": "Transmission Control Protocol",
        "value": "ephemeral → 443/80",
        "children": [
            {"name": "Src Port", "value": "ephemeral"},
            {"name": "Dst Port", "value": "443" if (row.get("url") or "").startswith("https") else "80"},
            {"name": "Stream index", "value": row.get("host") or ""},
            {"name": "Length", "value": str(frame_len)},
        ],
    })
    if (row.get("url") or "").startswith("https"):
        tree.append({
            "name": "Transport Layer Security",
            "value": row.get("protocol") or "TLS",
            "children": [
                {"name": "Record Layer", "value": "Application Data (decrypted by Kerf)"},
                {"name": "ALPN / version", "value": row.get("protocol") or "http/1.1"},
            ],
        })
    line, headers, body = _split_http(req)
    http_kids = [{"name": "Request Line", "value": line}]
    for k, v in headers:
        http_kids.append({"name": k, "value": v})
    http_kids.append({"name": "File Data", "value": f"{len(body)} bytes"})
    tree.append({"name": "Hypertext Transfer Protocol (request)", "value": line, "children": http_kids})
    if resp:
        rline, rheaders, rbody = _split_http(resp)
        rkids = [{"name": "Status Line", "value": rline}]
        for k, v in rheaders:
            rkids.append({"name": k, "value": v})
        rkids.append({"name": "File Data", "value": f"{len(rbody)} bytes"})
        tree.append({"name": "Hypertext Transfer Protocol (response)", "value": rline, "children": rkids})
    experts = expert_info(row)
    if experts:
        tree.append({
            "name": "Expert Info",
            "value": f"{len(experts)} item(s)",
            "children": [{"name": e["severity"], "value": e["text"]} for e in experts],
        })
    return tree


def expert_info(row: dict) -> list:
    out = []
    st = row.get("status") or 0
    if st >= 500:
        out.append({"severity": "error", "text": f"HTTP {st} server error"})
    elif st >= 400:
        out.append({"severity": "warn", "text": f"HTTP {st} client error"})
    mime = (row.get("mime") or "")
    body = row.get("resp_raw") or ""
    if "json" in mime and body.lstrip().endswith("\n") is False and "{" in body:
        pass
    if int(row.get("resp_length") or 0) > 1_000_000:
        out.append({"severity": "note", "text": "Large response body (>1MB)"})
    if (row.get("method") or "").upper() in ("POST", "PUT", "PATCH") and not row.get("req_length"):
        out.append({"severity": "chat", "text": f"{row.get('method')} with empty body"})
    req = row.get("req_raw") or ""
    if "authorization:" in req.lower() or "cookie:" in req.lower():
        out.append({"severity": "note", "text": "Request carries credentials"})
    return out


def hex_rows(data: bytes, *, base: int = 0) -> list:
    rows = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append({"off": base + i, "hex": hexpart, "ascii": ascii_})
    return rows


def follow_stream(rows: list[dict], host: str) -> dict:
    parts = []
    for r in rows:
        if (r.get("host") or "") != host:
            continue
        parts.append({"dir": "client", "raw": r.get("req_raw") or ""})
        if r.get("resp_raw"):
            parts.append({"dir": "server", "raw": r.get("resp_raw") or ""})
    text = []
    for p in parts:
        prefix = ">>> " if p["dir"] == "client" else "<<< "
        for line in (p["raw"] or "").splitlines():
            text.append(prefix + line)
        text.append("")
    return {"host": host, "exchanges": len(parts) // 2, "text": "\n".join(text)}


def conversations(rows: list[dict]) -> list:
    buckets: dict = {}
    for r in rows:
        host = r.get("host") or ""
        b = buckets.setdefault(host, {
            "host": host, "packets": 0, "bytes": 0, "methods": set(),
            "status": {}, "first": r.get("timestamp"), "last": r.get("timestamp"),
        })
        b["packets"] += 1
        b["bytes"] += int(r.get("req_length") or 0) + int(r.get("resp_length") or 0)
        if r.get("method"):
            b["methods"].add(r["method"])
        st = str(r.get("status") or "")
        if st:
            b["status"][st] = b["status"].get(st, 0) + 1
        b["last"] = r.get("timestamp")
    out = []
    for b in buckets.values():
        item = dict(b)
        item["methods"] = sorted(item["methods"])
        out.append(item)
    out.sort(key=lambda x: -x["packets"])
    return out


# --------------------------------------------------------------------------- #
# Reconstructed pcap (opens in any pcap viewer)
# --------------------------------------------------------------------------- #

def _ipv4(src: str, dst: str, payload: bytes) -> bytes:
    def ipb(s):
        return bytes(int(p) for p in s.split("."))
    ihl = 20
    total = ihl + 20 + len(payload)  # IP + TCP + data
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total, 0x3344, 0x4000, 64, 6, 0, ipb(src), ipb(dst),
    )
    chk = _checksum(ip)
    ip = ip[:10] + struct.pack("!H", chk) + ip[12:]
    return ip


def _tcp(src_port: int, dst_port: int, seq: int, payload: bytes, *, ack=0) -> bytes:
    flags = 0x18  # PSH+ACK
    offset = 5 << 4
    hdr = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, offset, flags,
                      8192, 0, 0)
    return hdr + payload


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _eth(payload: bytes) -> bytes:
    return b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00" + payload


def _pcap_packet(buf: bytearray, ts: float, frame: bytes) -> None:
    sec = int(ts)
    usec = int((ts - sec) * 1_000_000)
    buf.extend(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
    buf.extend(frame)


def export_pcap(rows: list[dict]) -> bytes:
    out = bytearray()
    out.extend(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    seq = 1000
    for i, row in enumerate(rows):
        ts = float(row.get("timestamp") or 0) or (1_700_000_000 + i)
        host = row.get("host") or "0.0.0.0"
        dst_ip = _host_ip(host)
        dst_port = 443 if (row.get("url") or "").startswith("https") else 80
        req = (row.get("req_raw") or "").encode("latin-1")
        resp = (row.get("resp_raw") or "").encode("latin-1")
        if req:
            tcp = _tcp(41000 + (i % 20000), dst_port, seq, req)
            ip = _ipv4("127.0.0.1", dst_ip, tcp)
            _pcap_packet(out, ts, _eth(ip + tcp))
            seq += len(req)
        if resp:
            tcp = _tcp(dst_port, 41000 + (i % 20000), 2000 + i * 50, resp)
            ip = _ipv4(dst_ip, "127.0.0.1", tcp)
            _pcap_packet(out, ts + 0.001, _eth(ip + tcp))
    return bytes(out)


def list_packets(history, *, expr: str = "", limit: int = 800) -> dict:
    need_body = "contains" in (expr or "").lower()
    summaries = history.list(hide_noise=False, limit=limit)
    t0 = summaries[-1]["timestamp"] if summaries else 0
    # list() is newest-first; pcap viewers are usually oldest-first
    summaries = list(reversed(summaries))
    t0 = summaries[0]["timestamp"] if summaries else 0
    packets = []
    tree = parse_filter(expr) if (expr or "").strip() else None
    for i, s in enumerate(summaries, start=1):
        row = dict(s)
        if need_body or tree:
            full = history.get(s["id"]) or s
            row.update(full)
        pkt = as_packet(row, no=i, t0=t0)
        if tree and not _eval(tree, {**row, **pkt}):
            continue
        pkt["no"] = len(packets) + 1
        packets.append(pkt)
    return {
        "filter": expr,
        "displayed": len(packets),
        "captured": len(summaries),
        "packets": packets,
        "conversations": conversations(summaries),
    }


def packet_detail(history, flow_id: str) -> dict | None:
    row = history.get(flow_id)
    if not row:
        return None
    req = (row.get("req_raw") or "").encode("latin-1")
    resp = (row.get("resp_raw") or "").encode("latin-1")
    combined = req + (b"\n\n" if req and resp else b"") + resp
    return {
        **as_packet(row, no=0, t0=row.get("timestamp") or 0),
        "tree": dissect(row),
        "expert": expert_info(row),
        "hex": hex_rows(combined),
        "req_raw": row.get("req_raw") or "",
        "resp_raw": row.get("resp_raw") or "",
        "byte_len": len(combined),
    }
