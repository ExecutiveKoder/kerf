"""
Target analyzer and engagement finds.

Reads captured history only. Surfaces parameters, methods, comments, hidden
fields, and script URLs — the mapping work testers otherwise do by hand.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from urllib.parse import parse_qsl, urlsplit

from modules.crawler import extract_urls

_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
_HIDDEN = re.compile(
    r"""<input[^>]+type=["']hidden["'][^>]*>""", re.I)
_NAME = re.compile(r"""name=["']([^"']+)["']""", re.I)
_VALUE = re.compile(r"""value=["']([^"']*)["']""", re.I)
_SCRIPT_SRC = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PATH_PARAM = re.compile(r"/[A-Za-z_][\w\-]*=")


def analyze_history(history, *, host: str = "", limit: int = 800) -> dict:
    rows = history.list(host=host or None, hide_noise=False, limit=limit)
    hosts: Counter = Counter()
    methods: Counter = Counter()
    status: Counter = Counter()
    mimes: Counter = Counter()
    params: Counter = Counter()
    words: Counter = Counter()
    comments: list = []
    hidden: list = []
    scripts: list = []
    emails: set = set()
    js_urls: list = []

    for summary in rows:
        full = history.get(summary["id"])
        if not full:
            continue
        hosts[full.get("host") or ""] += 1
        methods[full.get("method") or ""] += 1
        if full.get("status"):
            status[str(full["status"])] += 1
        if full.get("mime"):
            mimes[full["mime"]] += 1
        url = full.get("url") or ""
        for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            params[k] += 1
        body = full.get("resp_raw") or ""
        req = full.get("req_raw") or ""
        # form fields from request body
        if "application/x-www-form-urlencoded" in req.lower():
            _, _, rb = req.replace("\r\n", "\n").partition("\n\n")
            for k, _ in parse_qsl(rb, keep_blank_values=True):
                params[k] += 1
        if "application/json" in req.lower():
            _, _, rb = req.replace("\r\n", "\n").partition("\n\n")
            for m in re.finditer(r'"([A-Za-z_][\w\-]*)"\s*:', rb):
                params[m.group(1)] += 1
        mime = full.get("mime") or ""
        if "html" in mime or "<html" in body.lower()[:800]:
            for c in _COMMENT.findall(body):
                text = " ".join(c.split())
                if text and len(comments) < 80:
                    comments.append({"url": url, "text": text[:240]})
            for tag in _HIDDEN.findall(body):
                nm = _NAME.search(tag)
                if nm and len(hidden) < 80:
                    val = _VALUE.search(tag)
                    hidden.append({"url": url, "name": nm.group(1),
                                   "value": val.group(1) if val else ""})
            for src in _SCRIPT_SRC.findall(body):
                scripts.append({"url": url, "src": src})
        if "javascript" in mime or url.endswith(".js"):
            for u in extract_urls(url, body, mime=mime)[:30]:
                js_urls.append({"from": url, "url": u})
        emails.update(_EMAIL.findall(body)[:20])
        for token in re.findall(r"[A-Za-z][A-Za-z0-9_\-]{3,}", urlsplit(url).path):
            if token.lower() not in ("http", "https", "www", "com", "api"):
                words[token.lower()] += 1

    def _top(counter, n=30):
        return [{"name": k, "count": v} for k, v in counter.most_common(n) if k]

    return {
        "flows": len(rows),
        "hosts": _top(hosts),
        "methods": _top(methods),
        "status": _top(status),
        "mimes": _top(mimes),
        "parameters": _top(params, 60),
        "words": _top(words, 40),
        "comments": comments,
        "hidden_fields": hidden,
        "script_srcs": scripts[:80],
        "js_urls": js_urls[:120],
        "emails": sorted(emails)[:40],
    }
