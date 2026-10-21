"""
Tokens: analyze the randomness/entropy of a set of captured tokens (session
IDs, CSRF tokens, password-reset tokens). Weak tokens are predictable; this
measures that. Analysis only, over tokens you have already collected.
"""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy_bits(samples: list[str]) -> float:
    """Shannon entropy per character, averaged across all sample characters."""
    all_chars = "".join(samples)
    if not all_chars:
        return 0.0
    counts = Counter(all_chars)
    total = len(all_chars)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def char_position_entropy(samples: list[str]) -> list[float]:
    """Entropy at each character position (reveals fixed prefixes/suffixes)."""
    if not samples:
        return []
    width = min(len(s) for s in samples)
    result = []
    for pos in range(width):
        counts = Counter(s[pos] for s in samples)
        total = sum(counts.values())
        ent = -sum((n / total) * math.log2(n / total) for n in counts.values())
        result.append(round(ent, 4))
    return result


def analyze(samples: list[str]) -> dict:
    samples = [s for s in samples if s]
    if len(samples) < 2:
        return {"error": "need at least 2 samples"}

    lengths = [len(s) for s in samples]
    charset = sorted(set("".join(samples)))
    per_char = shannon_entropy_bits(samples)
    mean_len = sum(lengths) / len(lengths)
    # Rough total-entropy estimate assuming independence across positions.
    total_bits = per_char * mean_len

    unique_ratio = len(set(samples)) / len(samples)

    # Simple quality verdict.
    if total_bits >= 128 and unique_ratio == 1.0:
        verdict = "strong"
    elif total_bits >= 64 and unique_ratio > 0.95:
        verdict = "moderate"
    else:
        verdict = "weak"

    return {
        "sample_count": len(samples),
        "unique_ratio": round(unique_ratio, 4),
        "length_min": min(lengths),
        "length_max": max(lengths),
        "charset_size": len(charset),
        "entropy_bits_per_char": round(per_char, 4),
        "estimated_total_entropy_bits": round(total_bits, 2),
        "position_entropy": char_position_entropy(samples),
        "verdict": verdict,
    }
