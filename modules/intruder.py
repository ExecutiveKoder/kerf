"""
Payloads — automated, payload-driven request attacks.

You mark one or more insertion positions in a request template and point a set of
payloads at them. Kerf generates one request per payload combination, fires
them (optionally at full concurrency with no throttle), and tabulates the
responses so anomalies in status, length, timing, or content stand out.

Positions are marked with the section sign: wrap a value in `§...§`. Example:

    GET /item?id=§1§ HTTP/1.1
    Host: target

Attack types mirror the classic four:
  * sniper        — one payload set, one position at a time.
  * battering-ram — one payload set, same payload in every position at once.
  * pitchfork     — N payload sets, advanced in lockstep.
  * cluster-bomb  — N payload sets, full cartesian product.

Like Scan, Payloads is attack automation, so it honors the same
authorization gate: the target host must be in an authorized scope.
"""

from __future__ import annotations

import asyncio
import itertools
import re
import time
import uuid
from urllib.parse import urlsplit

from modules import payloads as payload_lib


MARK = "\u00a7"  # §


# --------------------------------------------------------------------------- #
# Template parsing
# --------------------------------------------------------------------------- #

def parse_positions(template: str):
    """Split a §-marked template into literal segments and position base values.

    Returns (literals, bases) with len(literals) == len(bases) + 1.
    """
    chunks = template.split(MARK)
    if len(chunks) % 2 == 0:
        raise ValueError("Unbalanced § markers: every position needs an opening "
                         "and closing §.")
    return chunks[0::2], chunks[1::2]


def build_request(literals, position_values) -> str:
    out = [literals[0]]
    for i, val in enumerate(position_values):
        out.append(val)
        out.append(literals[i + 1])
    return "".join(out)


def count_positions(template: str) -> int:
    try:
        _, bases = parse_positions(template)
        return len(bases)
    except ValueError:
        return 0


# --------------------------------------------------------------------------- #
# Attack combination generators
# --------------------------------------------------------------------------- #

def _combinations(attack_type: str, bases, sets):
    """Yield one list-of-position-values per request for the chosen attack."""
    n = len(bases)
    if attack_type == "sniper":
        pset = sets[0] if sets else []
        for i in range(n):
            for pv in pset:
                row = list(bases)
                row[i] = pv
                yield row
    elif attack_type == "battering-ram":
        pset = sets[0] if sets else []
        for pv in pset:
            yield [pv] * n
    elif attack_type == "pitchfork":
        for combo in zip(*sets[:n]):
            yield list(combo)
    elif attack_type == "cluster-bomb":
        for combo in itertools.product(*sets[:n]):
            yield list(combo)
    else:
        raise ValueError(f"unknown attack type: {attack_type}")


def _estimate(attack_type: str, bases, sets) -> int:
    n = len(bases)
    if not sets:
        return 0
    if attack_type == "sniper":
        return n * len(sets[0])
    if attack_type == "battering-ram":
        return len(sets[0])
    if attack_type == "pitchfork":
        return min(len(s) for s in sets[:n]) if sets[:n] else 0
    if attack_type == "cluster-bomb":
        total = 1
        for s in sets[:n]:
            total *= len(s)
        return total
    return 0


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #

class IntruderEngine:
    """Runs Payloads attacks and stores their results in memory."""

    def __init__(self, send_raw_coro, *, authz=None, hard_cap: int = 20000) -> None:
        # send_raw_coro(raw, scheme) -> Flow (reuses the proxy upstream path).
        self._send_raw = send_raw_coro
        self._authz = authz  # callable(url) -> bool, or None to allow
        self._attacks: dict = {}
        self.hard_cap = hard_cap

    # ------------------------------------------------------------- helpers

    def _base_url(self, raw: str, scheme: str) -> str:
        clean = raw.replace(MARK, "")
        lines = clean.replace("\r\n", "\n").split("\n")
        target = (lines[0].split(" ") + [""])[1] if lines else "/"
        host = ""
        for ln in lines[1:]:
            if ln.lower().startswith("host:"):
                host = ln.split(":", 1)[1].strip()
                break
        if target.startswith("http"):
            return target
        return f"{scheme}://{host}{target}"

    def _resolve_sets(self, attack_type: str, n_positions: int,
                      set_names, custom):
        """Turn requested payload-set names / custom lists into lists of strings."""
        sets = []
        if custom:
            sets = [list(c) for c in custom]
        elif set_names:
            for nm in set_names:
                ps = payload_lib.payload_set(nm)
                sets.append(ps.payloads if ps else [])
        if not sets:
            sets = [payload_lib.FUZZ_QUICK]
        if attack_type in ("sniper", "battering-ram"):
            sets = [sets[0]]
        else:
            # pitchfork/cluster-bomb want one set per position; reuse the last.
            while len(sets) < n_positions:
                sets.append(sets[-1])
        return sets

    # --------------------------------------------------------------- start

    def start(self, *, template: str, scheme: str = "https",
              attack_type: str = "sniper", set_names=None, custom=None,
              grep=None, extract: str = "", concurrency: int = 20,
        throttle_ms: int = 0) -> dict:
        literals, bases = parse_positions(template)
        if not bases:
            raise ValueError("No positions marked. Wrap a value in § markers.")

        url = self._base_url(template, scheme)
        if self._authz and not self._authz(url):
            raise PermissionError(
                "Payloads refused: target host is not in an authorized scope. "
                "Authorize it under Scan / Scope first.")

        sets = self._resolve_sets(attack_type, len(bases), set_names, custom)
        total = min(_estimate(attack_type, bases, sets), self.hard_cap)
        grep = [g for g in (grep or []) if g]

        attack_id = uuid.uuid4().hex[:12]
        state = {
            "id": attack_id, "attack_type": attack_type, "url": url,
            "status": "running", "total": total, "completed": 0,
            "started": time.time(), "finished": None,
            "grep": grep, "positions": len(bases), "results": [],
            "error": None,
        }
        self._attacks[attack_id] = state

        state["extract"] = extract or ""
        task = asyncio.create_task(self._run(
            state, literals, bases, sets, attack_type, scheme,
            grep, extract or "", concurrency, throttle_ms))
        state["_task"] = task
        return self.public_state(attack_id)

    async def _run(self, state, literals, bases, sets, attack_type, scheme,
                   grep, extract, concurrency, throttle_ms):
        sem = asyncio.Semaphore(max(1, concurrency))
        index = {"i": 0}
        lock = asyncio.Lock()

        async def one(position_values, idx):
            async with sem:
                raw = build_request(literals, position_values)
                t = time.perf_counter()
                try:
                    flow = await self._send_raw(raw, scheme)
                    elapsed = (time.perf_counter() - t) * 1000
                    resp = flow.response
                    body = resp.body if resp else b""
                    payload_str = "|".join(
                        v for v, b in zip(position_values, bases) if v != b) \
                        or "|".join(position_values)
                    matches = [g for g in grep if g.encode("latin-1", "ignore") in body]
                    reflected = payload_str and payload_str.encode(
                        "latin-1", "ignore") in body
                    extracted = ""
                    if extract:
                        try:
                            m = re.search(extract.encode("utf-8"), body)
                            if m:
                                extracted = (m.group(1) if m.lastindex
                                             else m.group(0)).decode("latin-1", "replace")
                        except re.error:
                            extracted = ""
                    row = {
                        "n": idx, "payload": payload_str,
                        "status": resp.status_code if resp else 0,
                        "length": len(body),
                        "time_ms": round(elapsed, 1),
                        "reflected": bool(reflected),
                        "matches": matches,
                        "extracted": extracted,
                    }
                except Exception as exc:
                    row = {"n": idx, "payload": "|".join(position_values),
                           "status": 0, "length": 0, "time_ms": 0,
                           "reflected": False, "matches": [],
                           "extracted": "", "error": repr(exc)}
                async with lock:
                    state["results"].append(row)
                    state["completed"] += 1
                if throttle_ms:
                    await asyncio.sleep(throttle_ms / 1000)

        tasks = []
        for row_values in _combinations(attack_type, bases, sets):
            i = index["i"]
            if i >= self.hard_cap:
                break
            index["i"] += 1
            tasks.append(asyncio.create_task(one(row_values, i)))
        try:
            await asyncio.gather(*tasks)
            state["status"] = "done"
        except asyncio.CancelledError:
            state["status"] = "stopped"
            raise
        except Exception as exc:
            state["status"] = "error"
            state["error"] = repr(exc)
        finally:
            state["finished"] = time.time()
            state["results"].sort(key=lambda r: r["n"])

    # ---------------------------------------------------------- introspect

    def public_state(self, attack_id: str, *, with_results: bool = True) -> dict:
        s = self._attacks.get(attack_id)
        if not s:
            return {}
        out = {k: v for k, v in s.items() if not k.startswith("_") and k != "results"}
        if with_results:
            out["results"] = s["results"]
        out["result_count"] = len(s["results"])
        return out

    def list_attacks(self) -> list:
        return [self.public_state(a, with_results=False)
                for a in sorted(self._attacks, key=lambda k: self._attacks[k]["started"],
                                reverse=True)]

    def stop(self, attack_id: str) -> bool:
        s = self._attacks.get(attack_id)
        if s and s.get("_task") and not s["_task"].done():
            s["_task"].cancel()
            return True
        return False

    @staticmethod
    def preview(template: str, attack_type: str, set_names, custom) -> dict:
        try:
            _, bases = parse_positions(template)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        sets = []
        if custom:
            sets = [list(c) for c in custom]
        elif set_names:
            for nm in set_names:
                ps = payload_lib.payload_set(nm)
                sets.append(ps.payloads if ps else [])
        if not sets:
            sets = [payload_lib.FUZZ_QUICK]
        if attack_type in ("sniper", "battering-ram"):
            sets = [sets[0]]
        return {"ok": True, "positions": len(bases),
                "estimated_requests": _estimate(attack_type, bases, sets)}
