# Writing active checks

> **Authorization first.** Active checks send crafted requests to a target to
> probe for vulnerabilities. Only run them against systems you own or have
> explicit, written permission to test. Unauthorized scanning is illegal in most
> jurisdictions (e.g. CFAA in the US, the Criminal Code in Canada). This project
> ships **no** active checks for that reason: you supply them, and you own the
> responsibility for where they run.

## Why none are bundled

The engine in `modules/active_scan.py` behaves identically against a system you
are authorized to test and one you are not. The code cannot tell the difference.
So the offensive logic (payloads, exploit-confirmation heuristics) is left to the
operator rather than shipped in the box. The engine gives you scope enforcement,
insertion-point discovery, scheduling, rate limiting, and an authorization gate.

## The interface

```python
from core.http_message import HttpRequest
from modules.active_scan import ActiveCheck, ActiveFinding, InsertionPoint


class MyCheck(ActiveCheck):
    name = "my-check"
    severity = "high"

    async def probe(self, base: HttpRequest, point: InsertionPoint, send) -> list[ActiveFinding]:
        # `point` tells you which parameter to vary (point.kind, point.name, point.value).
        # `send` is an async callable: send(HttpRequest) -> Flow, routed through the proxy.
        # Build a mutated request, send it, inspect the response, and decide whether
        # to return an ActiveFinding. Keep request volume modest and respect rate limits.
        return []


def register(api):
    api.add_active_check(MyCheck())
```

## Running them

Active scanning refuses to run until you assert authorized scope:

```python
engine.authorize_scope({"your-target.example.com"})
```

With an empty scope, nothing is in scope and nothing runs. This is intentional.

## Good-citizen rules for any check you write

- Gate on authorized scope; never scan out-of-scope hosts.
- Rate-limit. Don't DoS the target.
- Prefer safe, non-destructive probes. Never write/delete data as a "test".
- Log what you send so an engagement is auditable.
- Honor the target's `robots.txt` and rules of engagement.
