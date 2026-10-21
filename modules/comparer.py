"""
Compare: word- and byte-level diffing of two requests or responses, so you can
spot what changed between two flows (e.g. a valid vs invalid login response).
"""

from __future__ import annotations

import difflib


def word_diff(a: str, b: str) -> list[dict]:
    """Return a list of {op, text} segments at word granularity."""
    a_words = a.split()
    b_words = b.split()
    sm = difflib.SequenceMatcher(None, a_words, b_words)
    out: list[dict] = []
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op == "equal":
            out.append({"op": "equal", "text": " ".join(a_words[i1:i2])})
        elif op == "delete":
            out.append({"op": "delete", "text": " ".join(a_words[i1:i2])})
        elif op == "insert":
            out.append({"op": "insert", "text": " ".join(b_words[j1:j2])})
        elif op == "replace":
            out.append({"op": "delete", "text": " ".join(a_words[i1:i2])})
            out.append({"op": "insert", "text": " ".join(b_words[j1:j2])})
    return out


def unified(a: str, b: str, a_label: str = "a", b_label: str = "b") -> str:
    return "".join(
        difflib.unified_diff(
            a.splitlines(keepends=True),
            b.splitlines(keepends=True),
            fromfile=a_label,
            tofile=b_label,
        )
    )


def stats(a: str, b: str) -> dict:
    sm = difflib.SequenceMatcher(None, a, b)
    return {
        "ratio": round(sm.ratio(), 4),
        "len_a": len(a),
        "len_b": len(b),
        "identical": a == b,
    }
