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


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_COLOR = {"critical": "#9b1c1c", "high": "#d64545", "medium": "#c98a2b",
             "low": "#3d7bc4", "info": "#6b7280"}


def build_report(*, history, passive, active, interceptor,
                 project: str = "") -> dict:
    passive_findings = passive.report()
    active_findings = active.report()
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in passive_findings + active_findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
    # Versioned components only: the patch list. Unversioned ones can't be judged.
    inv = getattr(passive, "components", None)
    components = [c for c in (inv.public() if inv else []) if c.get("version")]
    for c in components:
        c["cves"] = c["cves"][:10]
    return {
        "components": components,
        "component_alerts": (inv.alerts[:20] if inv else []),
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "project": project,
        "tool": "Kerf",
        "scope": sorted(interceptor.scope_hosts),
        "active_scope": sorted(active.scope_hosts),
        "totals": {
            "flows": history.count(),
            "passive_findings": len(passive_findings),
            "active_findings": len(active_findings),
            "components_to_patch": sum(
                1 for c in components if c.get("status") == "vulnerable"),
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


def _exploit_tags(f: dict) -> str:
    out = ""
    kev = f.get("kev")
    if kev:
        out += ('<span class="sev" style="background:#7f1d1d">EXPLOITED'
                + (" · RANSOMWARE" if kev.get("ransomware") else "") + "</span>")
    epss = f.get("epss") or f.get("max_epss")
    if not kev and epss and epss >= 0.1:
        out += f'<span class="tag">EPSS {epss:.0%}</span>'
    return out


def _components_table(components: list[dict]) -> str:
    rows = []
    for c in components:
        status = c.get("status") or ""
        life = c.get("lifecycle") or {}
        if status == "vulnerable":
            sev = c.get("severity") or "medium"
            state = (f'<span class="sev" style="background:{SEV_COLOR.get(sev, "#6b7280")}">'
                     f'{html.escape(sev.upper())}</span>')
        else:
            state = html.escape({"ok": "up to date"}.get(status, status))
        exploited = _exploit_tags({"kev": {"ransomware": False} if c.get("kev_count") else None,
                                   "max_epss": c.get("max_epss")})
        cves = str(c.get("cve_count") or "")
        if c.get("kev_count"):
            cves += f" ({c['kev_count']} KEV)"
        eol = " · EOL" if life.get("eol") else ""
        rows.append(
            f"<tr><td><b>{html.escape(c['label'])}</b></td>"
            f"<td><code>{html.escape(c.get('display_version') or c['version'])}</code>{eol}</td>"
            f"<td>{state} {exploited}</td><td>{html.escape(cves)}</td>"
            f"<td>{html.escape(c.get('fix') or '')}</td>"
            f"<td><code>{html.escape(', '.join(c.get('hosts') or []))}</code></td></tr>")
    return ('<table class="comp"><thead><tr><th>Component</th><th>Version</th>'
            '<th>Status</th><th>CVEs</th><th>Fix</th><th>Hosts</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table>')


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
    if f.get("cve"):
        rows.append(f"<div><b>CVE:</b> <code>{html.escape(f['cve'])}</code>"
                    + (f" · CVSS {f['cvss']:.1f}" if f.get("cvss") is not None else "")
                    + "</div>")
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
        {_exploit_tags(f)}
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
    passives = data["passive_findings"]  # already exploit-first, then severity
    cards = "".join(_finding_card(f, "active") for f in actives)
    cards += "".join(_finding_card(f, "passive") for f in passives)
    if not cards:
        cards = '<p class="empty">No findings recorded.</p>'
    comps = data.get("components") or []
    comp_html = ""
    if comps:
        comp_html = ("<h2>Components to patch</h2><p class=\"meta\">Software seen by "
                     "version, checked against NVD, OSV, distro trackers, CISA KEV and "
                     "EPSS. Exploited first.</p>" + _components_table(comps))
    scope = ", ".join(html.escape(h) for h in data["scope"]) or "— none set —"
    project = html.escape(data["project"] or "Untitled session")

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Kerf report — {project}</title>
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
  table.comp {{ width:100%; border-collapse:collapse; background:#fff; font-size:13px;
    border:1px solid var(--line); border-radius:10px; overflow:hidden; }}
  table.comp th {{ text-align:left; font-size:11px; text-transform:uppercase; color:var(--dim);
    background:#f0f2f7; padding:8px 10px; }}
  table.comp td {{ padding:8px 10px; border-top:1px solid var(--line); vertical-align:top; }}
  table.comp .sev {{ display:inline-block; margin:1px 0; }}
  footer {{ margin-top:50px; color:var(--dim); font-size:12px; border-top:1px solid var(--line);
    padding-top:14px; }}
</style></head><body><div class="wrap">
  <header>
    <h1>Kerf security report</h1>
    <div class="meta">Project: <b>{project}</b> &nbsp;·&nbsp; Generated {html.escape(data['generated_at'])}
      &nbsp;·&nbsp; Scope: {scope}</div>
  </header>
  <div class="chips">
    {_chip("flows", data["totals"]["flows"])}
    {_chip("critical", c.get("critical", 0), SEV_COLOR["critical"])}
    {_chip("high", c["high"], SEV_COLOR["high"])}
    {_chip("medium", c["medium"], SEV_COLOR["medium"])}
    {_chip("low", c["low"], SEV_COLOR["low"])}
    {_chip("info", c["info"], SEV_COLOR["info"])}
    {_chip("active", data["totals"]["active_findings"])}
    {_chip("passive", data["totals"]["passive_findings"])}
    {_chip("to patch", data["totals"].get("components_to_patch", 0))}
  </div>
  {comp_html}
  <h2>Findings</h2>
  {cards}
  <footer>Generated by Kerf. Findings are evidence-based but should be manually
  verified. Test only systems you are authorized to assess.</footer>
</div></body></html>"""
