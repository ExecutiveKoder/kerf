# Kerf

**Website:** [kerf.software](https://kerf.software)

A clean-room web security proxy and manual-testing toolkit. It
gives you an intercepting HTTP/HTTPS proxy, searchable History, Replay,
Encode, Compare, Tokens, a **passive** scanner, and a plugin API, all behind
a local web UI. Personal use only — see [LICENSE](LICENSE).

It is written from scratch. It is not a fork, wrapper, or reimplementation of any
commercial tool's code. Where it overlaps in capability with tools like Burp
Suite or OWASP ZAP, that is because these are the standard building blocks of web
security testing, not because any proprietary code was copied.

> ## Use it only where you're authorized
> This is a tool for testing systems **you own or have explicit written
> permission to test**. Intercepting other people's traffic, or scanning systems
> you don't control, is illegal in most jurisdictions. You are responsible for
> staying inside that line. See [SECURITY.md](docs/SECURITY.md).

## What's included

| Component | Status | Notes |
|-----------|--------|-------|
| Intercepting proxy (HTTP/1.1 + HTTP/2 + WebSockets, HTTPS via own CA) | ✅ built | `core/proxy.py`, `core/ca.py` |
| History, host map, HAR import/export | ✅ built | `modules/history.py`, `modules/exportfmt.py` |
| Live intercept with filters | ✅ built | `modules/intercept.py` |
| Rewrite rules | ✅ built | `modules/rules.py` |
| Cookie jar / session handling | ✅ built | `modules/session.py` |
| Replay tabs + copy as curl/fetch/Python | ✅ built | `modules/repeater.py` |
| Isolated Chromium | ✅ built | `modules/browser.py` |
| Encode, Compare, Tokens | ✅ built | `modules/` |
| Endpoints + OpenAPI import | ✅ built | `modules/analyzer.py`, `modules/openapi.py` |
| In-scope crawler | ✅ built | `modules/crawler.py` |
| Log + local OAST listener | ✅ built | `modules/logger.py`, `modules/oast.py` |
| Dependency SCA + CycloneDX SBOM (OSV) | ✅ built | `modules/sca.py` |
| GitHub repo list + code/secret/OSV scan | ✅ built | `modules/repos.py` |
| Outbound Tor / SOCKS / HTTP + client certs | ✅ built | `modules/upstream.py` |
| BYO-model assistant | ✅ built | `modules/assistant.py` |
| Projects + HTML/JSON reports | ✅ built | `modules/projects.py`, `modules/reporting.py` |
| Passive scanner | ✅ built | `modules/passive_scanner.py` |
| Scan / Payloads | 🟡 engine | Authorized-scope only. No public exploit catalog. |

## Why the scan engine ships empty

Scan and Payloads send crafted payloads at a target
to probe for vulnerabilities. That code behaves identically whether the target is
yours or someone else's. So this project ships the **engine** (scope enforcement,
insertion-point discovery, scheduling, an authorization gate) but **no bundled
payloads or exploit-confirmation logic**.

If you need active scanning for an authorized engagement, you write your own
checks against the documented `ActiveCheck` interface and register them as
extensions. See [docs/WRITING_ACTIVE_CHECKS.md](docs/WRITING_ACTIVE_CHECKS.md).
The engine refuses to run until you assert an authorized scope.

This keeps the project useful without shipping a packaged exploitation toolkit.

## Install and run

Docker installs Python and starts Kerf. First run builds the image; later
runs are just start.

```bash
git clone https://github.com/ExecutiveKoder/kerf.git
cd kerf
docker compose up -d
```

Then:

1. Open the UI at http://127.0.0.1:8000
2. Accept the Kerf Personal Use License (no commercial use, no redistribution).
3. Go to **Setup**, download the CA, and install it in your browser/OS trust
   store (only on a machine you control).
4. Point your browser's HTTP/HTTPS proxy at `127.0.0.1:8080`.
5. Browse. Traffic shows up under **History**; passive findings under
   **Findings**.

History, the CA, and the attestation live in `./data` on the host.

Without Docker:

```bash
pip install -r requirements.txt
python main.py                 # proxy on 127.0.0.1:8080, UI on 127.0.0.1:8000
```

Set an in-scope host list under **Scope** to keep processing focused on the
systems you're authorized to test.

## Architecture

```
core/        intercepting proxy, CA, HTTP model, addon/interceptor chain
modules/     history, repeater, decoder, comparer, sequencer,
             passive_scanner, extensions, active_scan (scaffold)
ui/          FastAPI backend + single-page web UI
extensions/  drop-in plugins (an example passive check ships here)
docs/        writing checks, security/authorization notes
tests/       unit tests
```

Everything hangs off the **addon chain** (`core/interceptor.py`). History, the
passive scanner, and any plugin are all just addons that observe or mutate
flows. That's the seam you extend.

## Writing a plugin

Drop a `.py` file in `extensions/` exposing `register(api)`:

```python
from modules.passive_scanner import PassiveCheck, Finding

class MyCheck(PassiveCheck):
    name = "my-check"
    def run(self, flow):
        # inspect flow.request / flow.response, return a list of Finding
        return []

def register(api):
    api.add_passive_check(MyCheck())
```

See `extensions/example_passive_check.py` for a working example.

## Tests

```bash
python -m pytest tests/ -q
```

## Personal use

The app starts locked. Accept the Kerf Personal Use License to unlock every
feature. There is no key to mint or paste.

The [LICENSE](LICENSE) allows personal use only. You may not use Kerf
commercially and you may not redistribute it. For a commercial license,
email [accounts@kerf.software](mailto:accounts@kerf.software). Details:
[docs/BILLING.md](docs/BILLING.md).

## License

Kerf Personal Use License. Copyright © 2026 Smashrock Media Inc. See [LICENSE](LICENSE).

## Contributing

Pull requests to this official repository are welcome for passive checks,
UI, protocol support, and docs. That is not redistribution. For active
checks: keep payloads in your own engagement repos. This project does
not accept bundled attack payloads.
