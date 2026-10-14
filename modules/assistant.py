"""
AI operator — talk to SureGuard in natural language.

The assistant maps a user instruction onto the same screens and APIs a human
would use: open History, send a request to Repeater, arm a scan, start Intruder,
save a project, generate a report. It never bypasses the active-scan
authorization gate.

Providers (configured under Setup):
  * Local — Ollama, LM Studio, or any OpenAI-compatible endpoint
  * Frontier — OpenAI, Anthropic, Google Gemini
  * Gateway — OpenRouter (or a custom OpenAI-compatible URL)

Keys live in ~/.dastday/assistant.json on the operator's machine and are never
returned in full to the UI.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

from core.http_message import Flow
from modules.active_scan import discover_insertion_points
from modules.repeater import Repeater

CONFIG_DIR = Path(os.environ.get("DASTDAY_HOME", Path.home() / ".dastday"))
SETTINGS_PATH = CONFIG_DIR / "assistant.json"
CHAT_PATH = CONFIG_DIR / "assistant-chat.json"
HISTORY_KEEP = 80
# Desktop Chrome — looks like ordinary browser traffic, not a scanner.
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/192.168.1.5 Safari/537.36"
)

SCREENS = (
    "history", "intercept", "repeater", "decoder", "comparer", "sequencer",
    "findings", "active", "intruder", "projects", "reports", "scope", "setup",
)

PROVIDERS = {
    "openai": {
        "label": "OpenAI",
        "kind": "openai",
        "base_url": "https://api.openai.com/v1",
        "default_model": "",
        "needs_key": True,
        "hint": "Platform API key from platform.openai.com",
    },
    "anthropic": {
        "label": "Anthropic",
        "kind": "anthropic",
        "base_url": "https://api.anthropic.com",
        "default_model": "",
        "needs_key": True,
        "hint": "API key from console.anthropic.com",
    },
    "google": {
        "label": "Google Gemini",
        "kind": "google",
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "default_model": "",
        "needs_key": True,
        "hint": "API key from aistudio.google.com",
    },
    "openrouter": {
        "label": "OpenRouter",
        "kind": "openai",
        "base_url": "https://openrouter.ai/api/v1",
        "default_model": "",
        "needs_key": True,
        "hint": "Key from openrouter.ai — any routed model",
    },
    "ollama": {
        "label": "Ollama (local)",
        "kind": "openai",
        "base_url": "http://127.0.0.1:11434/v1",
        "default_model": "",
        "needs_key": False,
        "hint": "Runs locally. Start `ollama serve` first.",
    },
    "lmstudio": {
        "label": "LM Studio (local)",
        "kind": "openai",
        "base_url": "http://127.0.0.1:1234/v1",
        "default_model": "",
        "needs_key": False,
        "hint": "Enable the local server in LM Studio.",
    },
    "custom": {
        "label": "Custom (OpenAI-compatible)",
        "kind": "openai",
        "base_url": "http://127.0.0.1:8000/v1",
        "default_model": "",
        "needs_key": False,
        "hint": "Any OpenAI-compatible /v1/chat/completions endpoint.",
    },
}

SYSTEM_PROMPT = """You are SureGuard's operator. SureGuard is a local web-security
proxy and testing toolkit. The user tells you what they want; you pick the right
screen and call tools to do it.

Rules:
- Always navigate to the screen the user will want to see after the action.
- Only authorize an active scan or Intruder when the user names the host(s) they
  are allowed to test. Never invent a scope.
- Active scan and Intruder send crafted requests. Refuse if the user has not
  asserted authorization for those hosts.
- Prefer existing captured traffic (list_history / inspect_flow) over inventing
  requests. "Last request" means the most recent history entry.
- Keep replies short and concrete: what you did, what you found, what to look at.
- Do not dump huge raw HTTP or tool JSON. Summarize status, length, findings
  (severity + title). Never paste function-call payloads back to the user.
- If a tool errors (especially 403 locked scanner), explain how to arm it.
- You are given a live session briefing and the full chat so far. Use it.
  Remember hosts the user named, what is already authorized, last requests,
  and findings. Do not ask them to repeat that.

Playbook — finish the job:
When the user says to scan a host or site (e.g. "scan sehgal.ca"):
  1. If they named the host, authorize it (they asserted they may test it).
  2. Open the Active scan screen.
  3. Call scan_host so captured in-scope history is queued, not just one request.
  4. Wait for the job result and summarize findings in plain language.
When they say "scan the last / this request", use run_active_scan on that flow.
Opening the Intercept screen is navigate only. Do not enable intercept unless
they said to hold or intercept traffic.
If they say "scan" with no host and the scanner is already armed, scan_host on
the last in-scope host. If it is locked and they named no host, ask them to
authorize a host — do not stop after authorize-only when they also asked to scan.
"""

TOOLS = [
    {
        "name": "navigate",
        "description": "Open a SureGuard screen so the user can see the result.",
        "parameters": {
            "type": "object",
            "properties": {
                "screen": {"type": "string", "enum": list(SCREENS)},
            },
            "required": ["screen"],
        },
    },
    {
        "name": "get_status",
        "description": "Session snapshot: proxy, flows, findings, scan arming, project.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "list_history",
        "description": "Search captured proxy history.",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "method": {"type": "string"},
                "search": {"type": "string"},
                "limit": {"type": "integer"},
                "hide_noise": {"type": "boolean"},
            },
        },
    },
    {
        "name": "list_sitemap",
        "description": "Host/path tree of captured traffic.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "inspect_flow",
        "description": "Load a captured request/response by id and select it in the UI.",
        "parameters": {
            "type": "object",
            "properties": {"flow_id": {"type": "string"}},
            "required": ["flow_id"],
        },
    },
    {
        "name": "send_to_repeater",
        "description": "Open Repeater with a captured request loaded.",
        "parameters": {
            "type": "object",
            "properties": {"flow_id": {"type": "string"}},
            "required": ["flow_id"],
        },
    },
    {
        "name": "send_repeater",
        "description": "Send a raw HTTP request through Repeater.",
        "parameters": {
            "type": "object",
            "properties": {
                "raw": {"type": "string"},
                "scheme": {"type": "string", "enum": ["http", "https"]},
            },
            "required": ["raw"],
        },
    },
    {
        "name": "decode",
        "description": "Encode or decode a value (base64, url, hex, html, hashes).",
        "parameters": {
            "type": "object",
            "properties": {
                "transform": {
                    "type": "string",
                    "enum": [
                        "base64-encode", "base64-decode", "url-encode", "url-decode",
                        "hex-encode", "hex-decode", "html-encode", "html-decode",
                        "md5", "sha1", "sha256",
                    ],
                },
                "value": {"type": "string"},
            },
            "required": ["transform", "value"],
        },
    },
    {
        "name": "smart_decode",
        "description": "Try several decodes and return what looks valid.",
        "parameters": {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "required": ["value"],
        },
    },
    {
        "name": "compare",
        "description": "Diff two strings and open Comparer.",
        "parameters": {
            "type": "object",
            "properties": {"a": {"type": "string"}, "b": {"type": "string"}},
            "required": ["a", "b"],
        },
    },
    {
        "name": "analyze_tokens",
        "description": "Measure token entropy in Sequencer. One sample per list item.",
        "parameters": {
            "type": "object",
            "properties": {
                "samples": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["samples"],
        },
    },
    {
        "name": "list_passive_findings",
        "description": "Passive scanner findings from traffic already captured.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "authorize_active_scan",
        "description": "Arm the active scanner for hosts the user said they may test.",
        "parameters": {
            "type": "object",
            "properties": {
                "hosts": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["hosts"],
        },
    },
    {
        "name": "revoke_active_scan",
        "description": "Lock the active scanner again.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "discover_points",
        "description": "List insertion points on a captured request.",
        "parameters": {
            "type": "object",
            "properties": {"flow_id": {"type": "string"}},
            "required": ["flow_id"],
        },
    },
    {
        "name": "run_active_scan",
        "description": "Run the active scanner against one captured request. Scope must be armed.",
        "parameters": {
            "type": "object",
            "properties": {"flow_id": {"type": "string"}},
            "required": ["flow_id"],
        },
    },
    {
        "name": "scan_host",
        "description": "Queue an active scan of captured in-scope history for a host. Use this when the user says scan a site/host. Scope must be armed.",
        "parameters": {
            "type": "object",
            "properties": {"host": {"type": "string"}},
            "required": ["host"],
        },
    },
    {
        "name": "set_intercept",
        "description": "Turn live intercept on or off. Only call this when the user explicitly says to hold, intercept, or stop intercepting traffic — not when they just want to open the Intercept screen.",
        "parameters": {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean"},
                "hold_requests": {"type": "boolean"},
                "hold_responses": {"type": "boolean"},
            },
        },
    },
    {
        "name": "list_held",
        "description": "Requests currently held in the intercept queue.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "open_browser",
        "description": "Open SureGuard's isolated Chromium, already pointed at the proxy.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "list_active_findings",
        "description": "Findings from active scans this session.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "list_payload_sets",
        "description": "Named payload lists Intruder can use.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "start_intruder",
        "description": "Start an Intruder attack. Mark positions in the template with §. Scope must be armed.",
        "parameters": {
            "type": "object",
            "properties": {
                "template": {"type": "string"},
                "scheme": {"type": "string", "enum": ["http", "https"]},
                "attack_type": {
                    "type": "string",
                    "enum": ["sniper", "battering-ram", "pitchfork", "cluster-bomb"],
                },
                "set_names": {"type": "array", "items": {"type": "string"}},
                "grep": {"type": "array", "items": {"type": "string"}},
                "concurrency": {"type": "integer"},
            },
            "required": ["template"],
        },
    },
    {
        "name": "save_project",
        "description": "Snapshot history, scope, and findings to a named project.",
        "parameters": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "note": {"type": "string"},
            },
            "required": ["name"],
        },
    },
    {
        "name": "load_project",
        "description": "Resume a saved project.",
        "parameters": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    },
    {
        "name": "list_projects",
        "description": "Saved projects on disk.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "set_scope",
        "description": "Set passive in-scope hosts.",
        "parameters": {
            "type": "object",
            "properties": {
                "hosts": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["hosts"],
        },
    },
    {
        "name": "get_scope",
        "description": "Current passive scope.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "check_url",
        "description": "Send a simple GET through DastDay to see if a host or URL is reachable.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string",
                        "description": "Host or full URL, e.g. sehgal.ca or https://sehgal.ca/"},
                "scheme": {"type": "string", "enum": ["http", "https"]},
            },
            "required": ["url"],
        },
    },
]


def list_providers() -> list:
    return [
        {"id": k, **{kk: vv for kk, vv in v.items() if kk != "kind"}}
        for k, v in PROVIDERS.items()
    ]


def default_settings() -> dict:
    return {
        "provider": "openrouter",
        "model": "",
        "api_key": "",
        "base_url": "",
        "enabled": False,
        "models": [],
    }


def clean_reply(text: str) -> str:
    text = text or ""
    text = re.sub(r"```[\w-]*\n?([\s\S]*?)```", r"\1", text)
    text = re.sub(r"`{3,}", "", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"^[ \t]*[-*]\s+", "• ", text, flags=re.M)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _mask(key: str) -> str:
    if not key:
        return ""
    if len(key) <= 8:
        return "••••"
    return key[:3] + "••••" + key[-4:]


def public_settings(raw: dict) -> dict:
    p = raw.get("provider") or "openrouter"
    meta = PROVIDERS.get(p, PROVIDERS["openrouter"])
    models = [m for m in (raw.get("models") or []) if isinstance(m, str) and m]
    model = (raw.get("model") or "").strip()
    if model and models and model not in models:
        model = ""
    base = (raw.get("base_url") or "").strip() or meta["base_url"]
    key = raw.get("api_key") or ""
    return {
        "provider": p,
        "provider_label": meta["label"],
        "kind": meta["kind"],
        "model": model,
        "models": models,
        "base_url": base,
        "api_key_set": bool(key),
        "api_key_masked": _mask(key),
        "needs_key": meta["needs_key"],
        "hint": meta["hint"],
        "enabled": bool(raw.get("enabled")) and bool(model) and (
            bool(key) or not meta["needs_key"]),
        "configured": bool(model) and (bool(key) or not meta["needs_key"]),
    }


class Assistant:
    def __init__(self, ctx) -> None:
        self.ctx = ctx
        self._settings = self._load()
        self.history: list = self._load_chat()

    # ----------------------------------------------------------- settings

    def _load(self) -> dict:
        s = default_settings()
        try:
            if SETTINGS_PATH.exists():
                data = json.loads(SETTINGS_PATH.read_text())
                if isinstance(data, dict):
                    s.update({k: data.get(k, s[k]) for k in s})
                    models = [m for m in (s.get("models") or []) if isinstance(m, str)]
                    if s.get("model") and models and s["model"] not in models:
                        s["model"] = ""
        except Exception as exc:
            print(f"[assistant] settings load error: {exc!r}")
        return s

    def save_settings(self, patch: dict) -> dict:
        allowed = set(default_settings())
        prev_p = self._settings.get("provider")
        prev_b = self._settings.get("base_url")
        for k, v in patch.items():
            if k not in allowed:
                continue
            if k == "api_key" and isinstance(v, str) and "••" in v:
                continue  # masked placeholder — keep existing
            if k == "models" and not v:
                continue
            self._settings[k] = v
        if (("provider" in patch and patch.get("provider") != prev_p)
                or ("base_url" in patch and patch.get("base_url") != prev_b)):
            if "models" not in patch:
                self._settings["models"] = []
            if "model" not in patch:
                self._settings["model"] = ""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        SETTINGS_PATH.write_text(json.dumps(self._settings, indent=2))
        try:
            os.chmod(SETTINGS_PATH, 0o600)
        except OSError:
            pass
        return self.public()

    def public(self) -> dict:
        return public_settings(self._settings)

    def reset_conversation(self) -> None:
        self.history = []
        self._save_chat()

    def transcript(self) -> list:
        return [
            {"role": m.get("role"), "content": m.get("content") or ""}
            for m in self.history
            if m.get("role") in ("user", "assistant")
        ]

    def _load_chat(self) -> list:
        try:
            if CHAT_PATH.exists():
                data = json.loads(CHAT_PATH.read_text())
                if isinstance(data, list):
                    return [
                        {"role": m.get("role"), "content": m.get("content") or ""}
                        for m in data
                        if isinstance(m, dict) and m.get("role") in ("user", "assistant")
                    ][-HISTORY_KEEP:]
        except Exception as exc:
            print(f"[assistant] chat load error: {exc!r}")
        return []

    def _save_chat(self) -> None:
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            CHAT_PATH.write_text(json.dumps(self.history[-HISTORY_KEEP:], indent=2))
            try:
                os.chmod(CHAT_PATH, 0o600)
            except OSError:
                pass
        except Exception as exc:
            print(f"[assistant] chat save error: {exc!r}")

    def _remember(self, role: str, content: str) -> None:
        self.history.append({"role": role, "content": clean_reply(content) if role == "assistant" else content})
        if len(self.history) > HISTORY_KEEP:
            self.history = self.history[-HISTORY_KEEP:]
        self._save_chat()

    def _outbound_brief(self) -> str:
        try:
            u = self.ctx.upstream.public()
        except Exception:
            return "direct"
        if not u.get("active"):
            return "direct"
        return f"via {u.get('kind')} {u.get('host')}:{u.get('port')}"

    def _session_brief(self) -> str:
        ctx = self.ctx
        flows = ctx.history.list(limit=8)
        flow_lines = [
            f"- {f.get('method')} {f.get('host')}{f.get('path')} "
            f"status={f.get('status')} id={f.get('id')}"
            for f in flows
        ] or ["- no traffic captured yet"]
        active = ctx.active.report()[:8]
        passive = ctx.passive.report()[:8]
        def _f(items):
            if not items:
                return "- none"
            return "\n".join(
                f"- {i.get('severity')}: {i.get('title')} @ {i.get('url', '')}"
                for i in items)
        return (
            "Live session (authoritative — use this, do not ask the user to restate it):\n"
            f"- proxy: {ctx.proxy.host}:{ctx.proxy.port}\n"
            f"- project: {ctx.projects.current or '(none)'}\n"
            f"- flows captured: {ctx.history.count()}\n"
            f"- passive scope: {', '.join(sorted(ctx.interceptor.scope_hosts)) or '(open)'}\n"
            f"- active scanner: {'ARMED' if ctx.active.authorized else 'LOCKED'} "
            f"for {', '.join(sorted(ctx.active.scope_hosts)) or '(no hosts)'}\n"
            f"- intercept: {'ON' if ctx.intercept.enabled else 'off'} "
            f"({len(ctx.intercept._held)} held)\n"
            f"- outbound: {self._outbound_brief()}\n"
            f"- scan jobs: {len(ctx.active.jobs)}\n"
            f"- checks: {', '.join(ctx.active.check_names)}\n"
            "Recent traffic:\n" + "\n".join(flow_lines) + "\n"
            "Active findings:\n" + _f(active) + "\n"
            "Passive findings:\n" + _f(passive)
        )

    def _system_prompt(self) -> str:
        return SYSTEM_PROMPT + "\n\n" + self._session_brief()

    def _conversation_messages(self) -> list:
        out = []
        for m in self.history[-40:]:
            if m.get("role") in ("user", "assistant"):
                out.append({
                    "role": m["role"],
                    "content": (m.get("content") or "")[:3000],
                })
        return out

    # -------------------------------------------------------------- tools

    def _ui(self) -> dict:
        return {}

    async def _run_tool(self, name: str, args: dict, ui: dict):
        ctx = self.ctx
        args = args or {}

        if name == "navigate":
            screen = args.get("screen") or "history"
            if screen not in SCREENS:
                return {"error": f"unknown screen {screen}"}
            ui["screen"] = screen
            return {"opened": screen}

        if name == "get_status":
            return {
                "proxy": f"{ctx.proxy.host}:{ctx.proxy.port}",
                "flows": ctx.history.count(),
                "passive_findings": len(ctx.passive.findings),
                "active_findings": len(ctx.active.findings),
                "active_authorized": ctx.active.authorized,
                "active_scope": sorted(ctx.active.scope_hosts),
                "scope": sorted(ctx.interceptor.scope_hosts),
                "project": ctx.projects.current or "",
                "checks": ctx.active.check_names,
            }

        if name == "list_history":
            rows = ctx.history.list(
                host=args.get("host") or None,
                method=args.get("method") or None,
                search=args.get("search") or None,
                hide_noise=bool(args.get("hide_noise")),
                limit=int(args.get("limit") or 20),
            )
            ui.setdefault("screen", "history")
            if rows:
                ui["flow_id"] = rows[0]["id"]
            return {"count": len(rows), "flows": [
                {k: r[k] for k in ("id", "method", "host", "path", "status", "url", "mime")
                 if k in r}
                for r in rows
            ]}

        if name == "list_sitemap":
            ui.setdefault("screen", "history")
            tree = ctx.history.sitemap()
            return {"hosts": [
                {"host": h["host"], "count": h["count"],
                 "paths": [p["path"] for p in (h.get("paths") or [])[:30]]}
                for h in tree[:40]
            ]}

        if name == "inspect_flow":
            f = ctx.history.get(args["flow_id"])
            if not f:
                return {"error": "flow not found"}
            ui["screen"] = "history"
            ui["flow_id"] = f["id"]
            return {
                "id": f["id"], "method": f["method"], "host": f["host"],
                "path": f["path"], "status": f["status"], "url": f["url"],
                "req_preview": (f.get("req_raw") or "")[:2000],
                "resp_preview": (f.get("resp_raw") or "")[:2000],
            }

        if name == "send_to_repeater":
            f = ctx.history.get(args["flow_id"])
            if not f:
                return {"error": "flow not found"}
            scheme = urlsplit(f.get("url") or "").scheme or "https"
            ui["screen"] = "repeater"
            ui["flow_id"] = f["id"]
            ui["repeater"] = {"raw": f["req_raw"], "scheme": scheme}
            return {"loaded": True, "url": f["url"], "scheme": scheme}

        if name == "send_repeater":
            from modules import repeater as _  # noqa: F401
            raw = args["raw"]
            scheme = args.get("scheme") or "https"
            flow = await ctx.repeater.send_raw(raw, scheme)
            resp = flow.response
            ui["screen"] = "repeater"
            ui["repeater"] = {
                "raw": raw, "scheme": scheme,
                "response_raw": resp.raw().decode("latin-1") if resp else "",
                "status": resp.status_code if resp else None,
                "duration_ms": flow.duration_ms,
            }
            return {
                "status": resp.status_code if resp else None,
                "duration_ms": flow.duration_ms,
                "length": len(resp.body) if resp else 0,
            }

        if name == "decode":
            from modules import decoder
            result = decoder.apply(args["transform"], args["value"])
            ui["screen"] = "decoder"
            ui["decoder"] = {
                "transform": args["transform"],
                "value": args["value"],
                "result": result,
            }
            return {"result": result}

        if name == "smart_decode":
            from modules import decoder
            results = decoder.smart_decode(args["value"])
            ui["screen"] = "decoder"
            ui["decoder"] = {"value": args["value"], "result": json.dumps(results, indent=2)}
            return {"results": results}

        if name == "compare":
            from modules import comparer
            ui["screen"] = "comparer"
            ui["comparer"] = {"a": args["a"], "b": args["b"]}
            return {
                "stats": comparer.stats(args["a"], args["b"]),
                "word_diff": comparer.word_diff(args["a"], args["b"])[:80],
            }

        if name == "analyze_tokens":
            from modules import sequencer
            samples = args.get("samples") or []
            ui["screen"] = "sequencer"
            ui["sequencer"] = {"samples": "\n".join(samples)}
            return sequencer.analyze(samples)

        if name == "list_passive_findings":
            ui["screen"] = "findings"
            return ctx.passive.report()[:50]

        if name == "authorize_active_scan":
            hosts = [h.strip() for h in (args.get("hosts") or []) if h and h.strip()]
            if not hosts:
                return {"error": "name at least one host the user authorized"}
            ctx.active.authorize_scope(set(hosts))
            ui["screen"] = "active"
            ui["active_hosts"] = hosts
            return {"authorized": True, "scope": sorted(ctx.active.scope_hosts)}

        if name == "revoke_active_scan":
            ctx.active.revoke()
            ui["screen"] = "active"
            return {"authorized": False}

        if name == "discover_points":
            row = ctx.history.get(args["flow_id"])
            if not row:
                return {"error": "flow not found"}
            scheme = urlsplit(row["url"]).scheme or "https"
            req = Repeater.parse_raw(row["req_raw"], scheme)
            pts = discover_insertion_points(req)
            ui["screen"] = "active"
            ui["flow_id"] = row["id"]
            return {"url": req.url,
                    "points": [{"kind": p.kind, "name": p.name, "value": p.value}
                               for p in pts]}

        if name == "run_active_scan":
            row = ctx.history.get(args["flow_id"])
            if not row:
                return {"error": "flow not found"}
            scheme = urlsplit(row["url"]).scheme or "https"
            req = Repeater.parse_raw(row["req_raw"], scheme)
            ui["screen"] = "active"
            ui["flow_id"] = row["id"]
            found = await ctx.active.scan_flow(Flow(request=req))
            return {"new": [{"severity": f.severity, "title": f.title, "url": f.url}
                            for f in found],
                    "total": len(ctx.active.findings)}

        if name == "scan_host":
            import asyncio
            import time
            host = (args.get("host") or "").strip()
            if not host:
                latest = self._latest_flow()
                if not latest:
                    return {"error": "no captured traffic yet"}
                host = latest["host"]
            ui["screen"] = "active"
            ui["scan_host"] = host
            flows = self._flows_for_host(host)
            job = ctx.active.start_job(host, flows)
            deadline = time.time() + 90
            while time.time() < deadline:
                await asyncio.sleep(0.7)
                j = ctx.active.job(job["id"])
                if not j or j["status"] in ("done", "error"):
                    break
            j = ctx.active.job(job["id"]) or job
            issues = [i for i in ctx.active.report() if host in (i.get("url") or "")]
            return {
                "id": j.get("id"), "host": j.get("host"), "status": j.get("status"),
                "total": j.get("total"), "completed": j.get("completed"),
                "findings": j.get("findings"), "error": j.get("error"),
                "issues": [{"severity": i.get("severity"), "title": i.get("title"),
                            "url": i.get("url")} for i in issues[:20]],
            }

        if name == "set_intercept":
            ui["screen"] = "intercept"
            return ctx.intercept.configure(
                enabled=args.get("enabled"),
                hold_requests=args.get("hold_requests"),
                hold_responses=args.get("hold_responses"),
            )

        if name == "list_held":
            ui["screen"] = "intercept"
            st = ctx.intercept.status()
            return {"enabled": st["enabled"], "held": [
                {k: h[k] for k in ("id", "kind", "method", "host", "path") if k in h}
                for h in st.get("held") or []
            ]}

        if name == "open_browser":
            ui["screen"] = "intercept"
            return await ctx.browser.open(ctx.proxy.host, ctx.proxy.port)

        if name == "list_active_findings":
            ui["screen"] = "active"
            return ctx.active.report()[:50]

        if name == "list_payload_sets":
            from modules import payloads
            ui.setdefault("screen", "intruder")
            return payloads.list_payload_sets()

        if name == "start_intruder":
            template = args["template"]
            st = ctx.intruder.start(
                template=template,
                scheme=args.get("scheme") or "https",
                attack_type=args.get("attack_type") or "sniper",
                set_names=args.get("set_names") or ["fuzz-quick"],
                custom=None,
                grep=args.get("grep") or [],
                concurrency=int(args.get("concurrency") or 20),
            )
            ui["screen"] = "intruder"
            ui["intruder"] = {"template": template, "attack_id": st.get("id")}
            return st

        if name == "save_project":
            out = ctx.projects.save(args["name"], args.get("note") or "")
            ui["screen"] = "projects"
            return out

        if name == "load_project":
            out = ctx.projects.load(args["name"])
            ui["screen"] = "projects"
            return out

        if name == "list_projects":
            ui["screen"] = "projects"
            return ctx.projects.list()

        if name == "set_scope":
            hosts = [h.strip() for h in (args.get("hosts") or []) if h and h.strip()]
            ctx.interceptor.scope_hosts = set(hosts)
            ui["screen"] = "scope"
            ui["scope_hosts"] = hosts
            return {"hosts": sorted(ctx.interceptor.scope_hosts)}

        if name == "get_scope":
            ui["screen"] = "scope"
            return {"hosts": sorted(ctx.interceptor.scope_hosts)}

        if name == "check_url":
            raw_url = (args.get("url") or "").strip()
            if not raw_url:
                return {"error": "url required"}
            if "://" not in raw_url:
                scheme = args.get("scheme") or "https"
                raw_url = f"{scheme}://{raw_url}"
            parts = urlsplit(raw_url)
            host = parts.netloc or parts.path
            path = parts.path or "/"
            if parts.query:
                path = f"{path}?{parts.query}"
            scheme = parts.scheme or args.get("scheme") or "https"
            raw = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {DEFAULT_UA}\r\n"
                f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                f"Accept-Language: en-US,en;q=0.9\r\n\r\n"
            )
            flow = await ctx.repeater.send_raw(raw, scheme)
            resp = flow.response
            status = resp.status_code if resp else 0
            ui["screen"] = "repeater"
            ui["repeater"] = {
                "raw": raw.replace("\r\n", "\n"),
                "scheme": scheme,
                "response_raw": resp.raw().decode("latin-1") if resp else "",
                "status": status,
                "duration_ms": flow.duration_ms,
            }
            return {
                "ok": 200 <= status < 500,
                "up": status > 0 and status < 500,
                "url": f"{scheme}://{host}{path}",
                "status": status,
                "duration_ms": flow.duration_ms,
                "length": len(resp.body) if resp else 0,
            }

        return {"error": f"unknown tool {name}"}

    # ------------------------------------------------------- local router

    def _latest_flow(self, host: str = "", search: str = ""):
        rows = self.ctx.history.list(host=host or None, search=search or None, limit=1)
        return rows[0] if rows else None

    def _flows_for_host(self, host: str):
        rows = self.ctx.history.list(host=host, hide_noise=True, limit=80)
        flows = []
        for row in rows:
            full = self.ctx.history.get(row["id"])
            if not full or not full.get("req_raw"):
                continue
            scheme = urlsplit(full["url"]).scheme or "https"
            flows.append(Flow(request=Repeater.parse_raw(full["req_raw"], scheme)))
        return flows

    def _local_plan(self, text: str) -> Optional[list]:
        """Cheap intent match so the operator works before a model is connected."""
        t = text.strip()
        low = t.lower()
        calls = []

        for screen, aliases in (
            ("history", ("history", "proxy", "traffic")),
            ("intercept", ("intercept", "proxy intercept")),
            ("repeater", ("repeater",)),
            ("decoder", ("decoder", "decode", "encoder")),
            ("comparer", ("comparer", "compare", "diff")),
            ("sequencer", ("sequencer", "entropy", "tokens")),
            ("findings", ("findings", "passive")),
            ("active", ("active scan", "active scanner", "scanner")),
            ("intruder", ("intruder",)),
            ("projects", ("projects", "project")),
            ("reports", ("report", "reports")),
            ("scope", ("scope",)),
            ("setup", ("setup", "settings", "certificate", "ca cert")),
        ):
            if re.search(rf"\b(open|go to|show|take me to|switch to)\b.*\b{re.escape(aliases[0])}", low) \
                    or (low in aliases) or low == f"open {aliases[0]}":
                calls.append(("navigate", {"screen": screen}))
                return calls

        if re.search(r"\bintercept\s+off\b|\bstop intercept\b", low):
            calls.append(("set_intercept", {"enabled": False}))
            return calls
        if re.search(r"\bintercept\s+on\b|\bstart intercept\b|\bhold requests\b", low):
            calls.append(("set_intercept", {"enabled": True}))
            return calls
        if re.search(r"\bopen (the )?(browser|chromium)\b", low):
            calls.append(("open_browser", {}))
            return calls

        m = re.search(r"authorize\s+(.+)", low)
        if m or low.startswith("authorize "):
            rest = re.sub(r"^authorize\s+", "", t, flags=re.I)
            rest = re.sub(r"\s+and\s+.*$", "", rest, flags=re.I)
            hosts = [h.strip(" .,") for h in re.split(r"[\s,]+", rest)
                     if "." in h or h == "localhost" or re.match(r"\d+\.\d+", h)]
            if hosts:
                calls.append(("authorize_active_scan", {"hosts": hosts}))
                if "scan" in low:
                    calls.append(("scan_host", {"host": hosts[0]}))
                return calls

        m = re.search(
            r"\b(?:scan|active[\s-]?scan)\s+(?:the\s+)?(?:host\s+|site\s+)?"
            r"([a-z0-9.-]+\.[a-z]{2,}|\blocalhost\b|\d+\.\d+\.\d+\.\d+)",
            low)
        if m:
            host = m.group(1)
            armed = self.ctx.active.authorized and any(
                host == s or host.endswith("." + s) for s in self.ctx.active.scope_hosts)
            if not armed:
                calls.append(("authorize_active_scan", {"hosts": [host]}))
            calls.append(("scan_host", {"host": host}))
            return calls

        if re.search(r"\b(scan|active[\s-]?scan)\b", low):
            if re.search(r"\b(last|this request|selected)\b", low):
                flow = self._latest_flow()
                if flow:
                    calls.append(("run_active_scan", {"flow_id": flow["id"]}))
                    return calls
            host = None
            latest = self._latest_flow()
            scope = self.ctx.active.scope_hosts
            if latest and scope and any(
                latest["host"] == s or latest["host"].endswith("." + s) for s in scope):
                host = latest["host"]
            elif scope:
                host = sorted(scope)[0]
            elif latest:
                host = latest["host"]
            if host:
                calls.append(("scan_host", {"host": host}))
                return calls

        if "repeater" in low and ("send" in low or "last" in low or "this" in low):
            flow = self._latest_flow()
            if flow:
                calls.append(("send_to_repeater", {"flow_id": flow["id"]}))
                return calls

        m = re.search(r"(?:save|create)\s+project\s+(.+)", low)
        if m:
            calls.append(("save_project", {"name": m.group(1).strip().strip("\"'")}))
            return calls

        m = re.search(r"(?:load|resume|open)\s+project\s+(.+)", low)
        if m:
            calls.append(("load_project", {"name": m.group(1).strip().strip("\"'")}))
            return calls

        if re.search(r"\b(findings|what did you find|show issues)\b", low):
            calls.append(("list_active_findings", {}))
            calls.append(("list_passive_findings", {}))
            return calls

        if "report" in low and ("generate" in low or "open" in low or "make" in low):
            calls.append(("navigate", {"screen": "reports"}))
            return calls

        m = re.search(r"(?:base64|url|hex|html)\s*-?\s*(encode|decode)\s+(.+)", low)
        if m:
            kind = "base64" if "base64" in low else "url" if "url" in low else "hex" if "hex" in low else "html"
            calls.append(("decode", {
                "transform": f"{kind}-{m.group(1)}",
                "value": t[t.lower().index(m.group(2)):],
            }))
            return calls

        if re.search(r"\b(status|what's going on|what is going on)\b", low):
            calls.append(("get_status", {}))
            return calls

        m = re.search(
            r"(?:check|ping|reach|probe).{0,20}?\b([a-z0-9.-]+\.[a-z]{2,})\b"
            r"|\bis\s+([a-z0-9.-]+\.[a-z]{2,})\s+(?:up|down|online|reachable)",
            low)
        if m:
            host = m.group(1) or m.group(2)
            calls.append(("check_url", {"url": host}))
            return calls

        return None

    async def _exec_plan(self, calls: list) -> tuple:
        ui: dict = {}
        actions = []
        for name, args in calls:
            try:
                result = await self._run_tool(name, args, ui)
            except PermissionError as exc:
                result = {"error": str(exc)}
            except Exception as exc:
                result = {"error": repr(exc)}
            actions.append({"tool": name, "args": args, "result": result})
        return ui, actions

    def _summarize_local(self, actions: list) -> str:
        bits = []
        for a in actions:
            r = a.get("result") or {}
            if r.get("error"):
                bits.append(r["error"])
                continue
            if a["tool"] == "navigate":
                bits.append(f"Opened {r.get('opened')}.")
            elif a["tool"] == "run_active_scan":
                n = len(r.get("new") or [])
                titles = [f.get("title") for f in (r.get("new") or [])][:5]
                bits.append(f"Scan finished · {n} new finding(s)"
                            + (": " + "; ".join(titles) if titles else "."))
            elif a["tool"] == "scan_host":
                issues = r.get("issues") or []
                titles = [f"{i.get('severity')}: {i.get('title')}" for i in issues[:6]]
                bits.append(
                    f"Scanned {r.get('host')} · {r.get('completed', 0)}/{r.get('total', 0)} "
                    f"requests · {len(issues)} finding(s)"
                    + (": " + "; ".join(titles) if titles else ".")
                    + ("" if r.get("status") == "done" else f" Job {r.get('status')}."))
            elif a["tool"] == "set_intercept":
                bits.append("Intercept " + ("on." if r.get("enabled") else "off.")
                            + (f" {len(r.get('held') or [])} held." if r.get("held") else ""))
            elif a["tool"] == "open_browser":
                bits.append("Opened the SureGuard browser." if r.get("ok")
                            else (r.get("error") or "Could not open the browser."))
            elif a["tool"] == "authorize_active_scan":
                bits.append("Scanner armed for " + ", ".join(r.get("scope") or []) + ".")
            elif a["tool"] == "send_to_repeater":
                bits.append(f"Loaded {r.get('url')} into Repeater.")
            elif a["tool"] == "decode":
                bits.append("Decoded. Result is in Decoder.")
            elif a["tool"] == "save_project":
                bits.append(f"Saved project {r.get('name')}.")
            elif a["tool"] == "load_project":
                bits.append(f"Resumed {r.get('name')}.")
            elif a["tool"] == "get_status":
                bits.append(
                    f"{r.get('flows')} flows · {r.get('passive_findings')} passive · "
                    f"{r.get('active_findings')} active · scanner "
                    f"{'armed' if r.get('active_authorized') else 'locked'}.")
            elif a["tool"] == "check_url":
                bits.append(
                    f"{r.get('url')} → {r.get('status') or 'no response'}"
                    + (f" in {r.get('duration_ms'):.0f}ms" if r.get("duration_ms") else "")
                    + (". Reachable." if r.get("up") else ". Not reachable."))
            elif a["tool"] in ("list_active_findings", "list_passive_findings"):
                if isinstance(r, list):
                    bits.append(f"{len(r)} {a['tool'].replace('list_', '').replace('_', ' ')}.")
        return " ".join(bits) or "Done."

    # ---------------------------------------------------------- providers

    def _resolved(self) -> dict:
        p = self._settings.get("provider") or "openrouter"
        meta = PROVIDERS.get(p, PROVIDERS["custom"])
        return {
            "id": p,
            "kind": meta["kind"],
            "label": meta["label"],
            "model": public_settings(self._settings)["model"],
            "base_url": (self._settings.get("base_url") or "").strip() or meta["base_url"],
            "api_key": self._settings.get("api_key") or "",
            "needs_key": meta["needs_key"],
        }

    async def _http(self):
        import httpx
        return httpx

    async def test_connection(self) -> dict:
        cfg = self._resolved()
        if cfg["needs_key"] and not cfg["api_key"]:
            return {"ok": False, "error": "API key required for this provider."}
        if not cfg["model"]:
            return {"ok": False,
                    "error": "Pick a model from the dropdown after you connect."}
        try:
            text = await self._complete(
                cfg,
                [{"role": "user", "content": "Reply with the single word pong."}],
                tools=None,
            )
            reply = (text.get("content") or "").strip()
            return {"ok": True, "reply": reply[:200], "model": cfg["model"],
                    "provider": cfg["label"]}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def _names_from_payload(self, data) -> list:
        names = []
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("data") or data.get("models") or []
        else:
            items = []
        for it in items:
            if isinstance(it, str):
                names.append(it)
            elif isinstance(it, dict):
                names.append(it.get("id") or it.get("name") or it.get("model") or "")
        out, seen = [], set()
        for n in names:
            n = (n or "").strip()
            if n and n not in seen:
                seen.add(n)
                out.append(n)
        return out[:400]

    def _names_from_error(self, text: str) -> list:
        m = re.search(r"Available models:\s*(.+?)(?:\"|$)", text or "", re.I)
        if not m:
            return []
        return [p.strip() for p in m.group(1).split(",") if p.strip()]

    async def list_models(self) -> dict:
        cfg = self._resolved()
        httpx = await self._http()
        headers = {}
        if cfg["api_key"]:
            headers["Authorization"] = f"Bearer {cfg['api_key']}"
        base = cfg["base_url"].rstrip("/")
        roots = [base]
        # Ollama native tags live one level above /v1.
        if base.endswith("/v1"):
            roots.append(base[:-3])
        urls = []
        for root in roots:
            urls.append(root + "/models")
            urls.append(root + "/api/tags")
        last_err = ""
        try:
            if cfg["kind"] == "google":
                async with httpx.AsyncClient(timeout=15.0) as client:
                    r = await client.get(
                        f"{base}/models", params={"key": cfg["api_key"]})
                    r.raise_for_status()
                    names = self._names_from_payload(r.json())
                names = [n.split("/")[-1] for n in names]
                self._settings["models"] = names
                self.save_settings({})
                return {"ok": True, "models": names}
            if cfg["kind"] == "anthropic":
                names = [
                    "claude-sonnet-4-5", "claude-opus-4-1", "claude-haiku-4-5",
                ]
                self._settings["models"] = names
                self.save_settings({})
                return {"ok": True, "models": names}
            async with httpx.AsyncClient(timeout=15.0) as client:
                for url in urls:
                    try:
                        r = await client.get(url, headers=headers)
                    except Exception as exc:
                        last_err = str(exc)
                        continue
                    if r.status_code >= 400:
                        last_err = f"{r.status_code}: {r.text[:400]}"
                        parsed = self._names_from_error(r.text)
                        if parsed:
                            self._settings["models"] = parsed
                            self.save_settings({})
                            return {"ok": True, "models": parsed}
                        continue
                    names = self._names_from_payload(r.json())
                    if names:
                        self._settings["models"] = names
                        self.save_settings({})
                        return {"ok": True, "models": names}
            return {"ok": False, "models": [],
                    "error": last_err or "no models returned"}
        except Exception as exc:
            return {"ok": False, "models": [], "error": str(exc)}

    def _openai_wire_messages(self, messages: list) -> list:
        """Turn internal turns into OpenAI chat-completions wire format."""
        out = []
        for m in messages:
            role = m.get("role")
            if role == "tool":
                out.append({
                    "role": "tool",
                    "tool_call_id": str(m.get("tool_call_id") or "call_0"),
                    "content": m.get("content") or "",
                })
                continue
            if role == "assistant" and m.get("tool_calls"):
                tcs = []
                for i, tc in enumerate(m["tool_calls"]):
                    args = tc.get("args") if isinstance(tc, dict) else {}
                    argstr = args if isinstance(args, str) else json.dumps(args or {})
                    tcs.append({
                        "id": str(tc.get("id") or f"call_{i}_{tc.get('name', 'fn')}"),
                        "type": "function",
                        "function": {"name": tc.get("name"), "arguments": argstr},
                    })
                out.append({
                    "role": "assistant",
                    "content": m.get("content") or None,
                    "tool_calls": tcs,
                })
                continue
            out.append({"role": role, "content": m.get("content") or ""})
        return out

    def _flatten_after_tools(self, message: str, actions: list) -> list:
        summary = json.dumps(
            [{"tool": a["tool"], "args": a.get("args"), "result": a.get("result")}
             for a in actions],
            default=str)[:8000]
        msgs = [{"role": "system", "content": self._system_prompt()}]
        msgs.extend(self._conversation_messages())
        msgs.append({
            "role": "user",
            "content":
                "Tool results (already executed — do not call the same tools again):\n"
                f"{summary}\n\nAnswer the user now in plain language. Summarize what "
                "you did and any findings (severity + title). Never dump raw tool JSON "
                "or function-call payloads. Use the session briefing and chat above.",
        })
        return msgs

    def _openai_tools(self) -> list:
        return [{
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["parameters"],
            },
        } for t in TOOLS]

    def _anthropic_tools(self) -> list:
        return [{
            "name": t["name"],
            "description": t["description"],
            "input_schema": t["parameters"],
        } for t in TOOLS]

    async def _complete(self, cfg: dict, messages: list, tools) -> dict:
        httpx = await self._http()
        kind = cfg["kind"]
        timeout = 90.0

        if kind == "openai":
            headers = {"Content-Type": "application/json"}
            if cfg["api_key"]:
                headers["Authorization"] = f"Bearer {cfg['api_key']}"
            if cfg["id"] == "openrouter":
                headers["HTTP-Referer"] = "https://sureguard.local"
                headers["X-Title"] = "SureGuard"
            body: dict[str, Any] = {
                "model": cfg["model"],
                "messages": self._openai_wire_messages(messages),
            }
            if tools:
                body["tools"] = tools
                body["tool_choice"] = "auto"
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await client.post(
                    cfg["base_url"].rstrip("/") + "/chat/completions",
                    headers=headers, json=body)
                if r.status_code >= 400:
                    raise RuntimeError(f"{cfg['label']} {r.status_code}: {r.text[:400]}")
                msg = r.json()["choices"][0]["message"]
            tcs = []
            for tc in msg.get("tool_calls") or []:
                fn = tc.get("function") or {}
                raw = fn.get("arguments") or "{}"
                try:
                    parsed = json.loads(raw) if isinstance(raw, str) else raw
                except json.JSONDecodeError:
                    parsed = {}
                tcs.append({"id": tc.get("id") or fn.get("name"),
                            "name": fn.get("name"), "args": parsed})
            return {"content": msg.get("content") or "", "tool_calls": tcs,
                    "raw": msg}

        if kind == "anthropic":
            headers = {
                "Content-Type": "application/json",
                "x-api-key": cfg["api_key"],
                "anthropic-version": "2023-06-01",
            }
            sys_txt = ""
            a_msgs = []
            for m in messages:
                if m["role"] == "system":
                    sys_txt += m["content"] + "\n"
                    continue
                if m["role"] == "tool":
                    a_msgs.append({
                        "role": "user",
                        "content": [{
                            "type": "tool_result",
                            "tool_use_id": m.get("tool_call_id") or "",
                            "content": m.get("content") or "",
                        }],
                    })
                    continue
                if m["role"] == "assistant" and m.get("tool_calls"):
                    blocks = []
                    if m.get("content"):
                        blocks.append({"type": "text", "text": m["content"]})
                    for tc in m["tool_calls"]:
                        blocks.append({
                            "type": "tool_use",
                            "id": tc.get("id") or tc["name"],
                            "name": tc["name"],
                            "input": tc.get("args") or {},
                        })
                    a_msgs.append({"role": "assistant", "content": blocks})
                    continue
                a_msgs.append({"role": m["role"], "content": m.get("content") or ""})
            body = {
                "model": cfg["model"],
                "max_tokens": 2048,
                "system": sys_txt.strip() or SYSTEM_PROMPT,
                "messages": a_msgs,
            }
            if tools:
                body["tools"] = self._anthropic_tools()
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await client.post(
                    cfg["base_url"].rstrip("/") + "/v1/messages",
                    headers=headers, json=body)
                if r.status_code >= 400:
                    raise RuntimeError(f"{cfg['label']} {r.status_code}: {r.text[:400]}")
                data = r.json()
            content = ""
            tcs = []
            for block in data.get("content") or []:
                if block.get("type") == "text":
                    content += block.get("text") or ""
                elif block.get("type") == "tool_use":
                    tcs.append({"id": block.get("id"), "name": block.get("name"),
                                "args": block.get("input") or {}})
            return {"content": content, "tool_calls": tcs, "raw": data}

        if kind == "google":
            contents = []
            for m in messages:
                if m["role"] == "system":
                    continue
                role = "user" if m["role"] in ("user", "tool") else "model"
                parts = [{"text": m.get("content") or ""}]
                contents.append({"role": role, "parts": parts})
            body = {
                "contents": contents,
                "systemInstruction": {"parts": [{"text": self._system_prompt()}]},
            }
            if tools:
                body["tools"] = [{
                    "functionDeclarations": [{
                        "name": t["name"],
                        "description": t["description"],
                        "parameters": t["parameters"],
                    } for t in TOOLS]
                }]
            url = (f"{cfg['base_url'].rstrip('/')}/models/{cfg['model']}"
                   f":generateContent?key={cfg['api_key']}")
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await client.post(url, json=body)
                if r.status_code >= 400:
                    raise RuntimeError(f"{cfg['label']} {r.status_code}: {r.text[:400]}")
                data = r.json()
            parts = (((data.get("candidates") or [{}])[0].get("content") or {})
                     .get("parts") or [])
            content = ""
            tcs = []
            for p in parts:
                if p.get("text"):
                    content += p["text"]
                fc = p.get("functionCall")
                if fc:
                    tcs.append({"id": fc.get("name"), "name": fc.get("name"),
                                "args": fc.get("args") or {}})
            return {"content": content, "tool_calls": tcs, "raw": data}

        raise RuntimeError(f"unsupported provider kind {kind}")

    # -------------------------------------------------------------- chat

    async def chat(self, message: str) -> dict:
        message = (message or "").strip()
        if not message:
            return {"reply": "Tell me what you want to do.", "ui": {}, "actions": [],
                    "via": "none"}

        pub = self.public()
        ui: dict = {}
        actions: list = []

        if not pub["configured"]:
            plan = self._local_plan(message)
            if not plan:
                return {
                    "reply": "No model is connected yet. I can still handle simple "
                             "commands like “open active scan”, “authorize example.com”, "
                             "“scan the last request”, or “save project demo”. "
                             "For full natural language, add a provider under Setup.",
                    "ui": {"screen": "setup"} if "setup" in message.lower()
                    or "connect" in message.lower() or "model" in message.lower()
                    else {},
                    "actions": [],
                    "via": "local",
                }
            ui, actions = await self._exec_plan(plan)
            reply = self._summarize_local(actions)
            self._remember("user", message)
            self._remember("assistant", reply)
            return {"reply": clean_reply(reply), "ui": ui, "actions": _public_actions(actions),
                    "via": "local"}

        self._remember("user", message)
        cfg = self._resolved()
        messages = [{"role": "system", "content": self._system_prompt()}]
        messages.extend(self._conversation_messages())

        via = cfg["id"]
        local_provider = cfg["id"] in ("ollama", "lmstudio", "custom")
        try:
            for round_i in range(6):
                use_tools = self._openai_tools() if cfg["kind"] != "anthropic" else True
                # After tools have run, local servers often 500 if we replay
                # the same tool_calls. Flatten and ask for a final answer.
                if local_provider and actions:
                    messages = self._flatten_after_tools(message, actions)
                    use_tools = None
                out = await self._complete(cfg, messages, use_tools)
                tcs = out.get("tool_calls") or []
                if not tcs:
                    reply = (out.get("content") or "").strip() or (
                        self._summarize_local(actions) if actions else "Done.")
                    self._remember("assistant", reply)
                    return {"reply": clean_reply(reply), "ui": ui,
                            "actions": _public_actions(actions), "via": via}

                for tc in tcs:
                    name = tc.get("name") or ""
                    args = tc.get("args") or {}
                    if any(a["tool"] == name and a.get("args") == args for a in actions):
                        continue  # do not re-run an identical call
                    try:
                        result = await self._run_tool(name, args, ui)
                    except PermissionError as exc:
                        result = {"error": str(exc)}
                    except Exception as exc:
                        result = {"error": repr(exc)}
                    actions.append({"tool": name, "args": args, "result": result})

                if local_provider:
                    continue
                messages.append({
                    "role": "assistant",
                    "content": out.get("content") or "",
                    "tool_calls": tcs,
                })
                for tc in tcs:
                    result = next((a["result"] for a in actions
                                   if a["tool"] == tc.get("name")
                                   and a.get("args") == (tc.get("args") or {})),
                                  {})
                    messages.append({
                        "role": "tool",
                        "name": tc.get("name"),
                        "tool_call_id": tc.get("id") or tc.get("name"),
                        "content": json.dumps(result, default=str)[:8000],
                    })
            reply = self._summarize_local(actions) or "I hit the tool-call limit."
            self._remember("assistant", reply)
            return {"reply": clean_reply(reply), "ui": ui, "actions": _public_actions(actions),
                    "via": via}
        except Exception as exc:
            if actions:
                reply = self._summarize_local(actions)
                try:
                    out = await self._complete(
                        cfg, self._flatten_after_tools(message, actions), None)
                    reply = (out.get("content") or "").strip() or reply
                except Exception:
                    pass
                self._remember("assistant", reply)
                return {"reply": clean_reply(reply), "ui": ui,
                        "actions": _public_actions(actions), "via": via}
            plan = self._local_plan(message)
            if plan:
                ui, actions = await self._exec_plan(plan)
                reply = self._summarize_local(actions)
                self._remember("assistant", reply)
                return {"reply": clean_reply(reply), "ui": ui,
                        "actions": _public_actions(actions), "via": "local"}
            return {"reply": f"Model error: {exc}", "ui": ui,
                    "actions": _public_actions(actions), "via": via}


def _public_actions(actions: list) -> list:
    """Trim bulky tool results before sending them to the browser."""
    out = []
    for a in actions:
        r = a.get("result")
        if isinstance(r, list) and len(r) > 12:
            r = r[:12]
        if isinstance(r, dict) and isinstance(r.get("flows"), list) and len(r["flows"]) > 12:
            r = dict(r)
            r["flows"] = r["flows"][:12]
        out.append({"tool": a["tool"], "args": a.get("args") or {}, "result": r})
    return out
