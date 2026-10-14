"""
Scan report generation.

Collects passive and active findings plus session metadata and renders them as a
self-contained HTML document or a JSON object. No external assets, so a report
opens anywhere and travels well.
"""

from __future__ import annotations

import datetime
import html
import json

from modules import payloads


SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
SEV_COLOR = {"high": "#d64545", "medium": "#c98a2b",
             "low": "#3d7bc4", "info": "#6b7280"}


def build_report(*, history, passive, active, interceptor,
                 project: str = "") -> dict:
    passive_findings = passive.report()
    active_findings = active.report()
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for f in passive_findings + active_findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
    return {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "project": project,
        "tool": "SureGuard",
        "scope": sorted(interceptor.scope_hosts),
        "active_scope": sorted(active.scope_hosts),
        "totals": {
            "flows": history.count(),
            "passive_findings": len(passive_findings),
            "active_findings": len(active_findings),
            "by_severity": counts,
        },
        "active_findings": active_findings,
        "passive_findings": passive_findings,
        "issue_library": payloads.list_issue_types(),
    }


def render_json(data: dict) -> str:
    return json.dumps(data, indent=2)


def _chip(label: str, value, color: str = "#111") -> str:
    return (f'<div class="chip"><span class="n" style="color:{color}">{value}</span>'
            f'<span class="l">{html.escape(str(label))}</span></div>')


def _finding_card(f: dict, kind: str) -> str:
    sev = f.get("severity", "info")
    color = SEV_COLOR.get(sev, "#6b7280")
    issue = payloads.issue(f.get("issue_key", "")) if f.get("issue_key") else None
    rows = []
    if f.get("point"):
        rows.append(f"<div><b>Insertion point:</b> <code>{html.escape(f['point'])}</code></div>")
    if f.get("payload"):
        rows.append(f"<div><b>Payload:</b> <code>{html.escape(f['payload'])}</code></div>")
    if f.get("evidence"):
        rows.append(f"<div><b>Evidence:</b> <code>{html.escape(f['evidence'])}</code></div>")
    if f.get("confidence"):
        rows.append(f"<div><b>Confidence:</b> {html.escape(f['confidence'])}</div>")
    remediation = ""
    if issue:
        refs = "".join(f'<li><a href="{html.escape(r)}">{html.escape(r)}</a></li>'
                       for r in issue.references)
        remediation = (f'<div class="rem"><b>Remediation.</b> {html.escape(issue.remediation)}'
                       f'<ul>{refs}</ul></div>')
    return f"""
    <div class="card" style="border-left-color:{color}">
      <div class="ct">
        <span class="sev" style="background:{color}">{html.escape(sev.upper())}</span>
        <span class="title">{html.escape(f.get('title', ''))}</span>
        <span class="tag">{html.escape(kind)}</span>
        <span class="check">{html.escape(f.get('check', ''))}</span>
      </div>
      <div class="detail">{html.escape(f.get('detail', ''))}</div>
      <div class="url">{html.escape(f.get('url', ''))}</div>
      <div class="kv">{''.join(rows)}</div>
      {remediation}
    </div>"""


def render_html(data: dict) -> str:
    c = data["totals"]["by_severity"]
    actives = sorted(data["active_findings"], key=lambda f: SEV_ORDER.get(f["severity"], 9))
    passives = sorted(data["passive_findings"], key=lambda f: SEV_ORDER.get(f["severity"], 9))
    cards = "".join(_finding_card(f, "active") for f in actives)
    cards += "".join(_finding_card(f, "passive") for f in passives)
    if not cards:
        cards = '<p class="empty">No findings recorded.</p>'
    scope = ", ".join(html.escape(h) for h in data["scope"]) or "— none set —"
    project = html.escape(data["project"] or "Untitled session")

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>SureGuard report — {project}</title>
<style>
  :root {{ --ink:#1a2234; --dim:#5b6681; --line:#e2e6ef; --bg:#f6f7fb; }}
  * {{ box-sizing:border-box; }}
  body {{ font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;
    margin:0; background:var(--bg); color:var(--ink); line-height:1.55; }}
  .wrap {{ max-width:960px; margin:0 auto; padding:40px 24px 80px; }}
  header {{ border-bottom:2px solid var(--ink); padding-bottom:16px; margin-bottom:24px; }}
  h1 {{ margin:0; font-size:24px; }}
  h1 b {{ color:#e8a04f; }}
  .meta {{ color:var(--dim); font-size:13px; margin-top:6px; }}
  .chips {{ display:flex; gap:10px; flex-wrap:wrap; margin:22px 0; }}
  .chip {{ background:#fff; border:1px solid var(--line); border-radius:10px;
    padding:10px 16px; display:flex; flex-direction:column; min-width:92px; }}
  .chip .n {{ font-size:22px; font-weight:700; font-variant-numeric:tabular-nums; }}
  .chip .l {{ font-size:11px; color:var(--dim); text-transform:uppercase; letter-spacing:.4px; }}
  h2 {{ font-size:15px; text-transform:uppercase; letter-spacing:.5px; color:var(--dim);
    border-bottom:1px solid var(--line); padding-bottom:6px; margin:34px 0 16px; }}
  .card {{ background:#fff; border:1px solid var(--line); border-left-width:4px;
    border-radius:10px; padding:16px 18px; margin-bottom:14px; }}
  .ct {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
  .sev {{ color:#fff; font-size:10px; font-weight:700; padding:3px 9px; border-radius:5px;
    letter-spacing:.5px; }}
  .title {{ font-weight:700; font-size:15px; }}
  .tag {{ font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:var(--dim);
    border:1px solid var(--line); border-radius:5px; padding:2px 7px; }}
  .check {{ font-family:ui-monospace,Menlo,monospace; font-size:11px; color:var(--dim); margin-left:auto; }}
  .detail {{ margin:8px 0; }}
  .url {{ font-family:ui-monospace,Menlo,monospace; font-size:12px; color:var(--dim);
    word-break:break-all; }}
  .kv {{ font-size:13px; margin-top:8px; display:grid; gap:3px; }}
  code {{ font-family:ui-monospace,Menlo,monospace; background:#f0f2f7; padding:1px 5px;
    border-radius:4px; font-size:12px; word-break:break-all; }}
  .rem {{ margin-top:10px; padding:10px 12px; background:#f0f7f0; border-radius:8px; font-size:13px; }}
  .rem ul {{ margin:6px 0 0; padding-left:18px; }}
  .rem a {{ color:#2b6cb0; }}
  .empty {{ color:var(--dim); }}
  footer {{ margin-top:50px; color:var(--dim); font-size:12px; border-top:1px solid var(--line);
    padding-top:14px; }}
</style></head><body><div class="wrap">
  <header>
    <h1>Dast<b>·</b>Day security report</h1>
    <div class="meta">Project: <b>{project}</b> &nbsp;·&nbsp; Generated {html.escape(data['generated_at'])}
      &nbsp;·&nbsp; Scope: {scope}</div>
  </header>
  <div class="chips">
    {_chip("flows", data["totals"]["flows"])}
    {_chip("high", c["high"], SEV_COLOR["high"])}
    {_chip("medium", c["medium"], SEV_COLOR["medium"])}
    {_chip("low", c["low"], SEV_COLOR["low"])}
    {_chip("info", c["info"], SEV_COLOR["info"])}
    {_chip("active", data["totals"]["active_findings"])}
    {_chip("passive", data["totals"]["passive_findings"])}
  </div>
  <h2>Findings</h2>
  {cards}
  <footer>Generated by SureGuard. Findings are evidence-based but should be manually
  verified. Test only systems you are authorized to assess.</footer>
</div></body></html>"""
