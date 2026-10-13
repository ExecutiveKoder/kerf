# DastDay

An open-source, clean-room web security proxy and manual-testing toolkit. It
gives you an intercepting HTTP/HTTPS proxy, searchable traffic history, a
request repeater, encoder/decoder, comparer, token sequencer, a **passive**
scanner, and a plugin API, all behind a local web UI.

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
| Intercepting proxy (HTTP + HTTPS via own CA) | ✅ built | `core/proxy.py`, `core/ca.py` |
| HTTP history (search, filter, scope) | ✅ built | SQLite-backed, `modules/history.py` |
| Repeater (edit + replay one request) | ✅ built | `modules/repeater.py` |
| Decoder / Encoder (base64, url, hex, html, hashes) | ✅ built | `modules/decoder.py` |
| Comparer (word/byte diffing) | ✅ built | `modules/comparer.py` |
| Sequencer (token entropy analysis) | ✅ built | `modules/sequencer.py` |
| Passive scanner (headers, cookies, info leaks, mixed content) | ✅ built | `modules/passive_scanner.py` |
| Extension / plugin API | ✅ built | `modules/extensions.py` |
| Web UI | ✅ built | `ui/` |
| **Active scanner engine** | 🟡 scaffold only | Ships with **no attack checks** — you supply them for authorized targets. See below. |
| **Intruder-style attack automation** | 🟡 scaffold only | Same: insertion-point plumbing provided, payloads are operator-supplied. |

## Why the active scanner ships empty

Active scanning and Intruder-style automation send crafted payloads at a target
to probe for vulnerabilities. That code behaves identically whether the target is
yours or someone else's. So this project ships the **engine** (scope enforcement,
insertion-point discovery, scheduling, an authorization gate) but **no bundled
payloads or exploit-confirmation logic**.

If you need active scanning for an authorized engagement, you write your own
checks against the documented `ActiveCheck` interface and register them as
extensions. See [docs/WRITING_ACTIVE_CHECKS.md](docs/WRITING_ACTIVE_CHECKS.md).
The engine refuses to run until you assert an authorized scope.

This keeps the project genuinely useful and fully open-source without shipping a
packaged exploitation toolkit.

## Install

```bash
git clone <your-fork-url> DastDay
cd DastDay
pip install -r requirements.txt
```

## Run

```bash
python main.py                 # proxy on 127.0.0.1:8080, UI on 127.0.0.1:8000
```

Then:

1. Open the UI at http://127.0.0.1:8000
2. Go to **Setup**, download the CA, and install it in your browser/OS trust
   store (only on a machine you control).
3. Point your browser's HTTP/HTTPS proxy at `127.0.0.1:8080`.
4. Browse. Traffic shows up under **Proxy History**; passive findings under
   **Findings**.

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

## License

MIT. See [LICENSE](LICENSE).

## Contributing

Passive checks, UI improvements, protocol support (HTTP/2, WebSocket depth), and
documentation are all welcome. For active checks: contribute them to your own
engagement repos, not here. This project does not accept bundled attack payloads.
