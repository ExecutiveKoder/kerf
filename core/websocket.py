"""
WebSocket upgrade detection and frame logging.

After a 101, we splice bytes both ways and parse frames so the logger/history
can show what was said. No payload generation.
"""

from __future__ import annotations

import struct

from core.http_message import HttpRequest


def is_websocket(req: HttpRequest) -> bool:
    upgrade = (req.header("Upgrade") or "").lower()
    conn = (req.header("Connection") or "").lower()
    return "websocket" in upgrade or ("upgrade" in conn and "websocket" in upgrade)


def decode_frame(buf: bytes) -> tuple[dict | None, int]:
    """Return (frame, bytes_consumed) or (None, 0) if incomplete."""
    if len(buf) < 2:
        return None, 0
    b0, b1 = buf[0], buf[1]
    fin = bool(b0 & 0x80)
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F
    idx = 2
    if length == 126:
        if len(buf) < 4:
            return None, 0
        length = struct.unpack("!H", buf[2:4])[0]
        idx = 4
    elif length == 127:
        if len(buf) < 10:
            return None, 0
        length = struct.unpack("!Q", buf[2:10])[0]
        idx = 10
    mask = b""
    if masked:
        if len(buf) < idx + 4:
            return None, 0
        mask = buf[idx:idx + 4]
        idx += 4
    if len(buf) < idx + length:
        return None, 0
    payload = bytearray(buf[idx:idx + length])
    if masked:
        for i in range(len(payload)):
            payload[i] ^= mask[i % 4]
    names = {0x0: "cont", 0x1: "text", 0x2: "binary", 0x8: "close",
             0x9: "ping", 0xA: "pong"}
    text = ""
    if opcode == 0x1:
        text = bytes(payload).decode("utf-8", "replace")
    return ({
        "fin": fin,
        "opcode": names.get(opcode, hex(opcode)),
        "length": length,
        "text": text[:400],
    }, idx + length)


def drain_frames(buf: bytearray) -> list[dict]:
    frames = []
    while True:
        frame, n = decode_frame(bytes(buf))
        if not frame or n <= 0:
            break
        del buf[:n]
        frames.append(frame)
    return frames
