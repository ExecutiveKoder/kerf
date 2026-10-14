"""
OpenAPI / Swagger import.

Turns a spec into request templates you can send to Repeater or the sitemap
without browsing every endpoint by hand.
"""

from __future__ import annotations

import json
from urllib.parse import urljoin

from core.http_message import HttpRequest, Flow
from modules.repeater import Repeater

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/192.168.1.5 Safari/537.36")


def _load(text: str) -> dict:
    text = text.strip()
    if not text:
        raise ValueError("empty spec")
    if text[0] in "{[":
        return json.loads(text)
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text)
    except Exception as exc:
        raise ValueError(f"spec is not JSON and YAML parse failed: {exc}") from exc


def _sample(schema: dict | None, components: dict) -> object:
    if not schema:
        return {}
    if "$ref" in schema:
        ref = schema["$ref"].split("/")[-1]
        return _sample((components.get("schemas") or {}).get(ref) or {}, components)
    t = schema.get("type")
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if t == "object" or schema.get("properties"):
        out = {}
        for k, v in (schema.get("properties") or {}).items():
            out[k] = _sample(v, components)
        return out
    if t == "array":
        return [_sample(schema.get("items") or {}, components)]
    if t == "integer" or t == "number":
        return 0
    if t == "boolean":
        return False
    return schema.get("format") or "string"


def parse_spec(text: str, *, base_url: str = "") -> list[dict]:
    spec = _load(text)
    servers = spec.get("servers") or []
    if not base_url:
        if servers and isinstance(servers[0], dict):
            base_url = servers[0].get("url") or ""
        elif spec.get("host"):
            scheme = (spec.get("schemes") or ["https"])[0]
            base = spec.get("basePath") or ""
            base_url = f"{scheme}://{spec['host']}{base}"
    base_url = base_url.rstrip("/")
    paths = spec.get("paths") or {}
    components = spec.get("components") or {}
    out = []
    for path, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        for method, op in ops.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete",
                                      "head", "options"):
                continue
            if not isinstance(op, dict):
                continue
            url = urljoin(base_url + "/", path.lstrip("/")) if base_url else path
            headers = [("Host", url.split("/")[2] if "://" in url else "localhost"),
                       ("User-Agent", UA),
                       ("Accept", "application/json")]
            body = b""
            for media in ((op.get("requestBody") or {}).get("content") or {}):
                schema = (op["requestBody"]["content"][media] or {}).get("schema")
                sample = _sample(schema, components)
                if "json" in media:
                    body = json.dumps(sample).encode()
                    headers.append(("Content-Type", "application/json"))
                    break
            raw_req = HttpRequest(method.upper(), url if "://" in url else f"https://example{url}",
                                  headers, body)
            out.append({
                "method": method.upper(),
                "path": path,
                "url": raw_req.url,
                "summary": op.get("summary") or op.get("operationId") or "",
                "raw": raw_req.raw().decode("latin-1"),
                "scheme": "https" if raw_req.url.startswith("https") else "http",
            })
    return out


def flows_from_spec(text: str, *, base_url: str = "") -> list[Flow]:
    items = parse_spec(text, base_url=base_url)
    flows = []
    for item in items:
        req = Repeater.parse_raw(item["raw"], item["scheme"])
        flows.append(Flow(request=req))
    return flows
