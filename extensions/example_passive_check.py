"""
Example extension: a passive check that flags responses which set a session
cookie without rotating it on what looks like a login response.

This is passive (reads traffic that already happened) and is safe to run against
any target. Use it as a template for your own passive checks.

Drop a file like this in the extensions/ directory and it loads automatically.
"""

from core.http_message import Flow
from modules.passive_scanner import PassiveCheck, Finding


class CacheControlOnAuthCheck(PassiveCheck):
    name = "cache-control-on-auth"

    def run(self, flow: Flow) -> list[Finding]:
        resp = flow.response
        if not resp:
            return []
        # Heuristic: responses that set an auth-ish cookie should not be cacheable.
        sets_auth_cookie = any(
            k.lower() == "set-cookie" and
            any(t in v.lower() for t in ("session", "auth", "token"))
            for k, v in resp.headers
        )
        if not sets_auth_cookie:
            return []
        cc = (resp.header("cache-control") or "").lower()
        if "no-store" not in cc and "no-cache" not in cc:
            return [Finding(
                "low",
                "Auth response is cacheable",
                "A response setting a session/auth cookie lacks Cache-Control: "
                "no-store; intermediaries may cache sensitive content.",
                flow.id, flow.request.url, self.name,
            )]
        return []


def register(api):
    api.add_passive_check(CacheControlOnAuthCheck())
