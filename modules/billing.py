"""
Issuer helpers for Kerf personal-use keys.

Complimentary keys are minted from your machine (vendor key). This copy
does not sell or accept commercial keys.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
import httpx

from modules.brand import NAME, PLANS, SLUG
from modules import license as lic

AMOUNTS = {"team": 2900, "cloud": 7900}  # cents, USD
ISSUER_FILE = Path(__file__).resolve().parent.parent / "issuer.json"


def _home() -> Path:
    return Path(os.environ.get("DASTDAY_HOME", Path.home() / ".dastday"))


def _settings_path() -> Path:
    return _home() / "billing.json"


def _ledger_path() -> Path:
    return _home() / "issued.json"


def _default() -> dict:
    return {
        "stripe_secret": "",
        "webhook_secret": "",
        "public_url": "",
        "price_team": "",
        "price_cloud": "",
        "link_team": "",
        "link_cloud": "",
        "webhook_id": "",
    }


def _load() -> dict:
    s = _default()
    try:
        if _settings_path().exists():
            data = json.loads(_settings_path().read_text())
            if isinstance(data, dict):
                s.update({k: data.get(k, s[k]) for k in s})
    except Exception:
        pass
    if not s["stripe_secret"]:
        s["stripe_secret"] = (os.environ.get("KERF_STRIPE_SECRET")
                              or os.environ.get("STRIPE_SECRET_KEY") or "")
    if not s["webhook_secret"]:
        s["webhook_secret"] = (os.environ.get("KERF_STRIPE_WEBHOOK")
                               or os.environ.get("STRIPE_WEBHOOK_SECRET") or "")
    if not s["public_url"]:
        s["public_url"] = os.environ.get("KERF_PUBLIC_URL") or ""
    if not s["price_team"]:
        s["price_team"] = os.environ.get("KERF_PRICE_TEAM") or ""
    if not s["price_cloud"]:
        s["price_cloud"] = os.environ.get("KERF_PRICE_CLOUD") or ""
    return s


def _save(s: dict) -> None:
    path = _settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(s, indent=2))


def _write_issuer(url: str) -> None:
    url = (url or "").rstrip("/")
    if not url:
        return
    ISSUER_FILE.write_text(json.dumps({"url": url}, indent=2) + "\n")


def issuer_url() -> str:
    for src in (
        os.environ.get("KERF_ISSUER_URL") or "",
        (_load().get("public_url") or "") if lic.can_issue() else "",
    ):
        if src.strip():
            return src.strip().rstrip("/")
    try:
        if ISSUER_FILE.exists():
            url = (json.loads(ISSUER_FILE.read_text()).get("url") or "").rstrip("/")
            if url:
                return url
    except Exception:
        pass
    return ""


def _secret() -> str:
    return (_load().get("stripe_secret") or "").strip()


def configured() -> bool:
    s = _load()
    return bool(s.get("stripe_secret") and s.get("price_team") and s.get("price_cloud"))


def public_url() -> str:
    return (_load().get("public_url") or issuer_url()
            or "http://127.0.0.1:8010").rstrip("/")


def _mask(value: str) -> str:
    v = value or ""
    if len(v) < 10:
        return "••••" if v else ""
    return v[:7] + "…" + v[-4:]


def available() -> dict:
    s = _load()
    return {
        "product": NAME,
        "stripe": configured(),
        "seller": lic.can_issue(),
        "issuer": issuer_url(),
        "public_url": s.get("public_url") or "",
        "price_team": s.get("price_team") or "",
        "price_cloud": s.get("price_cloud") or "",
        "link_team": s.get("link_team") or "",
        "link_cloud": s.get("link_cloud") or "",
        "stripe_secret": _mask(s.get("stripe_secret") or ""),
        "webhook_secret": _mask(s.get("webhook_secret") or ""),
        "has_secret": bool(s.get("stripe_secret")),
        "plans": [
            {"id": k, **v, "price_id": s.get(f"price_{k}", "")}
            for k, v in PLANS.items()
        ],
        "issued": ledger()[:20],
    }


def ledger() -> list:
    try:
        if _ledger_path().exists():
            rows = json.loads(_ledger_path().read_text())
            if isinstance(rows, list):
                return rows
    except Exception:
        pass
    return []


def _remember(row: dict) -> dict:
    rows = [r for r in ledger() if r.get("session_id") != row.get("session_id")
            or not row.get("session_id")]
    rows.insert(0, row)
    path = _ledger_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows[:200], indent=2))
    return row


def _find_issued(session_id: str) -> dict | None:
    for row in ledger():
        if row.get("session_id") == session_id and row.get("key"):
            return row
    return None


def configure(patch: dict) -> dict:
    s = _load()
    for k in _default():
        if k not in patch or patch[k] is None:
            continue
        val = str(patch[k]).strip()
        if "…" in val or "•" in val:
            continue
        s[k] = val
    _save(s)
    if s.get("public_url"):
        _write_issuer(s["public_url"])
    return available()


def _stripe():
    try:
        import stripe  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "Stripe package missing. From Setup → License click Enable billing "
            "after Stripe is installed, or pip install stripe.") from exc
    key = _secret()
    if not key:
        raise RuntimeError("Paste a Stripe secret key under Setup → License.")
    stripe.api_key = key
    return stripe


def _find_or_create_price(stripe, plan: str) -> str:
    s = _load()
    existing = s.get(f"price_{plan}") or ""
    if existing:
        try:
            stripe.Price.retrieve(existing)
            return existing
        except Exception:
            pass
    products = stripe.Product.list(limit=100, active=True)
    product = None
    for p in products.auto_paging_iter():
        if (p.get("metadata") or {}).get("kerf_plan") == plan:
            product = p
            break
        if product is None and p.get("name") == f"{NAME} {PLANS[plan]['label']}":
            product = p
    if product is None:
        product = stripe.Product.create(
            name=f"{NAME} {PLANS[plan]['label']}",
            metadata={"kerf_plan": plan, "kerf": SLUG},
        )
    for price in stripe.Price.list(product=product.id, active=True, limit=20).auto_paging_iter():
        if price.get("recurring", {}).get("interval") == "month" \
                and int(price.get("unit_amount") or 0) == AMOUNTS[plan]:
            return price.id
    created = stripe.Price.create(
        product=product.id,
        currency="usd",
        unit_amount=AMOUNTS[plan],
        recurring={"interval": "month"},
        metadata={"kerf_plan": plan},
    )
    return created.id


def _ensure_payment_link(stripe, plan: str, price_id: str) -> str:
    s = _load()
    existing = s.get(f"link_{plan}") or ""
    if existing:
        return existing
    base = public_url()
    link = stripe.PaymentLink.create(
        line_items=[{"price": price_id, "quantity": 1}],
        after_completion={
            "type": "redirect",
            "redirect": {"url": base + "/?paid=1"},
        },
        metadata={"kerf_plan": plan},
        allow_promotion_codes=True,
    )
    return link.url


def _ensure_webhook(stripe, s: dict) -> dict:
    url = (s.get("public_url") or "").rstrip("/")
    if not url or "127.0.0.1" in url or "localhost" in url:
        return s
    target = url + "/api/billing/webhook"
    if s.get("webhook_id") and s.get("webhook_secret"):
        return s
    for ep in stripe.WebhookEndpoint.list(limit=50).auto_paging_iter():
        if ep.get("url") == target:
            s["webhook_id"] = ep.id
            return s
    created = stripe.WebhookEndpoint.create(
        url=target,
        enabled_events=["checkout.session.completed", "invoice.paid"],
        metadata={"kerf": SLUG},
    )
    s["webhook_id"] = created.id
    secret = getattr(created, "secret", None) or created.get("secret")
    if secret:
        s["webhook_secret"] = secret
    return s


def enable() -> dict:
    if not lic.can_issue():
        raise RuntimeError("This copy cannot issue licenses (no signing key).")
    stripe = _stripe()
    s = _load()
    s["price_team"] = _find_or_create_price(stripe, "team")
    s["price_cloud"] = _find_or_create_price(stripe, "cloud")
    if s.get("public_url"):
        s["link_team"] = _ensure_payment_link(stripe, "team", s["price_team"])
        s["link_cloud"] = _ensure_payment_link(stripe, "cloud", s["price_cloud"])
        s = _ensure_webhook(stripe, s)
        _write_issuer(s["public_url"])
    _save(s)
    return available()


def gift(*, email: str, plan: str = "personal", days: int = 365, seats: int = 1) -> dict:
    if not lic.can_issue():
        raise RuntimeError("This copy cannot issue licenses.")
    plan = (plan or "personal").lower()
    if plan != "personal":
        raise ValueError("commercial keys are not issued. This copy only signs personal-use keys.")
    token = lic.issue(email=email, days=days, seats=seats)
    row = _remember({
        "ts": time.time(),
        "email": email,
        "plan": plan,
        "days": days,
        "seats": seats,
        "key": token,
        "session_id": "",
        "source": "gift",
    })
    return row


async def checkout(plan: str, email: str = "", return_url: str = "") -> dict:
    plan = (plan or "").lower()
    if plan != "personal":
        raise ValueError(
            "commercial checkout is not offered. This copy only signs "
            "personal-use keys; commercial keys are rejected.")
    dest = (return_url or public_url()).rstrip("/")
    if lic.can_issue() and _secret():
        s = _load()
        if not (s.get(f"price_{plan}")):
            enable()
            s = _load()
        stripe = _stripe()
        price = s.get(f"price_{plan}") or ""
        if not price:
            raise RuntimeError("Enable billing first — prices were not created.")
        session = stripe.checkout.Session.create(
            mode="subscription",
            line_items=[{"price": price, "quantity": 1}],
            customer_email=email or None,
            success_url=dest + "/?paid=1&session_id={CHECKOUT_SESSION_ID}",
            cancel_url=dest + "/?paid=0",
            metadata={"kerf_plan": plan, "kerf_email": email},
        )
        return {"url": session.url, "id": session.id}
    remote = issuer_url()
    if not remote:
        raise RuntimeError(
            "Payments are not enabled yet. The seller turns them on under "
            "Setup → License (paste a Stripe key and click Enable billing).")
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            remote + "/api/billing/checkout",
            json={"plan": plan, "email": email, "return_url": dest},
        )
        r.raise_for_status()
        return r.json()


def catalog() -> dict:
    return available()


def _mint_from_session(session) -> dict:
    email = (session.get("customer_details") or {}).get("email") \
        or session.get("customer_email") \
        or (session.get("metadata") or {}).get("kerf_email") \
        or "customer@unknown"
    plan = (session.get("metadata") or {}).get("kerf_plan") or "personal"
    if plan != "personal":
        raise ValueError("commercial keys are not issued")
    sid = session.get("id") or ""
    found = _find_issued(sid) if sid else None
    if found:
        return found
    token = lic.issue(email=email, days=365, seats=1)
    return _remember({
        "ts": time.time(),
        "email": email,
        "plan": plan,
        "days": 365,
        "seats": 1,
        "key": token,
        "session_id": sid,
        "source": "stripe",
    })


async def claim(session_id: str, store: lic.LicenseStore | None = None) -> dict:
    session_id = (session_id or "").strip()
    if not session_id:
        raise ValueError("session_id required")
    found = _find_issued(session_id)
    if found:
        out = dict(found)
        if store is not None and out.get("key"):
            out["license"] = store.activate(out["key"], attest=True)
        return out
    if lic.can_issue() and _secret():
        stripe = _stripe()
        session = stripe.checkout.Session.retrieve(session_id)
        if session.get("payment_status") not in ("paid", "no_payment_required") \
                and session.get("status") != "complete":
            raise RuntimeError("checkout is not complete yet")
        row = _mint_from_session(session)
        if store is not None and row.get("key"):
            row = dict(row)
            row["license"] = store.activate(row["key"], attest=True)
        return row
    remote = issuer_url()
    if not remote:
        raise RuntimeError("No license issuer is configured.")
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            remote + "/api/billing/claim",
            json={"session_id": session_id, "install": False},
        )
        r.raise_for_status()
        data = r.json()
    if store is not None and data.get("key"):
        data["license"] = store.activate(data["key"], attest=True)
    return data


async def handle_webhook(payload: bytes, sig: str,
                         store: lic.LicenseStore | None = None) -> dict:
    secret = (_load().get("webhook_secret") or "").strip()
    if not secret:
        raise RuntimeError("Webhook secret is not set. Click Enable billing.")
    stripe = _stripe()
    event = stripe.Webhook.construct_event(payload, sig, secret)
    kind = event["type"]
    if kind not in ("checkout.session.completed", "invoice.paid"):
        return {"ok": True, "ignored": kind}
    obj = event["data"]["object"]
    sid = obj.get("id") if kind == "checkout.session.completed" \
        else (obj.get("parent") or {}).get("subscription_details", {}).get("subscription") \
        or obj.get("subscription")
    if kind == "invoice.paid":
        # Invoice has no checkout session; skip unless we can map it.
        return {"ok": True, "ignored": kind}
    return await claim(sid, store)


_TUNNEL: subprocess.Popen | None = None


def tunnel_status() -> dict:
    running = _TUNNEL is not None and _TUNNEL.poll() is None
    return {"running": running, "url": _load().get("public_url") or ""}


def start_tunnel(local_url: str = "http://127.0.0.1:8010") -> dict:
    global _TUNNEL
    if _TUNNEL is not None and _TUNNEL.poll() is None:
        return tunnel_status()
    bin_name = "cloudflared"
    try:
        _TUNNEL = subprocess.Popen(
            [bin_name, "tunnel", "--url", local_url, "--no-autoupdate"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "Install Cloudflare's tunnel (cloudflared) and click again, "
            "or paste a public URL from ngrok / a VPS.") from exc
    url = ""
    assert _TUNNEL.stdout is not None
    deadline = time.time() + 12
    while time.time() < deadline:
        line = _TUNNEL.stdout.readline()
        if not line:
            if _TUNNEL.poll() is not None:
                break
            continue
        m = re.search(r"https://[a-zA-Z0-9.-]+\.trycloudflare\.com", line)
        if m:
            url = m.group(0)
            break
    if not url:
        raise RuntimeError("Tunnel started but no public URL appeared yet.")
    s = _load()
    s["public_url"] = url
    _save(s)
    _write_issuer(url)
    if _secret():
        try:
            enable()
        except Exception:
            pass
    return {"running": True, "url": url}


def stop_tunnel() -> dict:
    global _TUNNEL
    if _TUNNEL and _TUNNEL.poll() is None:
        _TUNNEL.terminate()
    _TUNNEL = None
    return {"running": False, "url": _load().get("public_url") or ""}
