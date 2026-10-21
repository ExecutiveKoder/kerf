"""
Example extension built on the active-scan API.

This shows how a plugin can:
registering an active check, contributing a payload set, and adding an entry to
the scan-issue library. It loads automatically from the extensions directory.

The check here is a compact open-redirect probe: it substitutes an attacker URL
into a parameter and flags a 3xx Location that points at the injected host. Like
all active checks it only runs against hosts in an authorized scope.
"""

from urllib.parse import urlsplit

from modules.active_scan import ActiveCheck, ActiveFinding, apply_payload

REDIRECT_PAYLOADS = [
    "https://dastday.example.evil/",
    "//dastday.example.evil/",
    "https:dastday.example.evil",
]
EVIL_HOST = "dastday.example.evil"


class OpenRedirectCheck(ActiveCheck):
    name = "open-redirect"
    issue_key = "open-redirect"

    async def probe(self, base, point, send):
        # Only parameters whose value looks like a URL/path are interesting.
        if not (point.value.startswith(("http", "/")) or "url" in point.name.lower()
                or "redirect" in point.name.lower() or "next" in point.name.lower()):
            return []
        for pl in REDIRECT_PAYLOADS:
            flow = await send(apply_payload(base, point, pl))
            resp = flow.response
            if resp and 300 <= resp.status_code < 400:
                loc = resp.header("location") or ""
                if EVIL_HOST in (urlsplit(loc).netloc or loc):
                    return [ActiveFinding(
                        "medium", "Open redirect",
                        f"Parameter '{point.name}' controls the redirect target; "
                        f"the server issued a redirect to an attacker-chosen host.",
                        base.url, self.name, issue_key=self.issue_key,
                        point=f"{point.kind}:{point.name}", payload=pl,
                        evidence=f"Location: {loc}")]
        return []


def register(api):
    api.add_issue_type(
        "open-redirect", "Open redirect", "medium",
        "A redirect destination is controlled by user input, letting an attacker "
        "send victims from a trusted origin to an arbitrary site.",
        "Validate redirect targets against an allowlist of known-safe paths or "
        "hosts; never redirect to a raw user-supplied URL.",
        ["https://cwe.mitre.org/data/definitions/601.html"])
    api.add_payload_set("open-redirect", "redirect",
                        "Open-redirect probe URLs", REDIRECT_PAYLOADS)
    api.add_active_check(OpenRedirectCheck())
