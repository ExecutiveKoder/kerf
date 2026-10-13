"""
Decoder/Encoder: transform selected data between common encodings used in web
traffic. Pure functions, no network. Mirrors Burp's Decoder tab.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import html
import urllib.parse
import zlib

# ------------------------------------------------------------------ encode


def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.b64decode(data + pad)


def url_encode(data: str) -> str:
    return urllib.parse.quote(data, safe="")


def url_decode(data: str) -> str:
    return urllib.parse.unquote(data)


def hex_encode(data: bytes) -> str:
    return data.hex()


def hex_decode(data: str) -> bytes:
    return bytes.fromhex(data.strip().replace(" ", ""))


def html_encode(data: str) -> str:
    return html.escape(data)


def html_decode(data: str) -> str:
    return html.unescape(data)


def gzip_decode(data: bytes) -> bytes:
    return gzip.decompress(data)


def deflate_decode(data: bytes) -> bytes:
    try:
        return zlib.decompress(data)
    except zlib.error:
        return zlib.decompress(data, -zlib.MAX_WBITS)


# -------------------------------------------------------------------- hash


def hash_all(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }


# --------------------------------------------------------------- dispatch

TRANSFORMS = {
    "base64-encode": lambda s: b64_encode(s.encode()),
    "base64-decode": lambda s: b64_decode(s).decode("latin-1"),
    "url-encode": url_encode,
    "url-decode": url_decode,
    "hex-encode": lambda s: hex_encode(s.encode()),
    "hex-decode": lambda s: hex_decode(s).decode("latin-1"),
    "html-encode": html_encode,
    "html-decode": html_decode,
    "md5": lambda s: hashlib.md5(s.encode()).hexdigest(),
    "sha1": lambda s: hashlib.sha1(s.encode()).hexdigest(),
    "sha256": lambda s: hashlib.sha256(s.encode()).hexdigest(),
}


def apply(transform: str, value: str) -> str:
    fn = TRANSFORMS.get(transform)
    if not fn:
        raise ValueError(f"unknown transform: {transform}")
    return fn(value)


def smart_decode(value: str) -> dict[str, str]:
    """Best-effort attempt at several decodings, for the 'what is this?' case."""
    out: dict[str, str] = {}
    for name in ("base64-decode", "url-decode", "hex-decode", "html-decode"):
        try:
            out[name] = apply(name, value)
        except Exception:
            pass
    return out
