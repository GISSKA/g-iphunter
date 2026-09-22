"""Self-contained HTML report generator (dark theme)."""
from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, List

from g_iphunter.core.models import IPReport

_CSS = """
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2.5rem 1.5rem;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Ubuntu, sans-serif;
  background: #0b1220; color: #e2e8f0; line-height: 1.5;
}
h1, h2, h3 { color: #f8fafc; margin: 0 0 .6rem 0; }
h1 { font-size: 1.6rem; letter-spacing: .3px; }
h2 { font-size: 1.2rem; margin-top: 2rem; border-bottom: 1px solid #1e293b; padding-bottom: .4rem; }
h3 { font-size: 1rem; color: #cbd5e1; }
.container { max-width: 1100px; margin: 0 auto; }
.header {
  display: flex; justify-content: space-between; align-items: baseline;
  border-bottom: 2px solid #0f766e; padding-bottom: 1rem; margin-bottom: 2rem;
}
.brand { color: #2dd4bf; font-weight: 700; letter-spacing: .5px; }
.meta { color: #94a3b8; font-size: .85rem; }
.card {
  background: #111a2e; border: 1px solid #1e293b; border-radius: 10px;
  padding: 1.2rem 1.4rem; margin-bottom: 1.2rem;
}
.ip-title { display: flex; justify-content: space-between; align-items: center; gap: 1rem; flex-wrap: wrap; }
.ip-address { font-family: "JetBrains Mono", Consolas, monospace; color: #7dd3fc; font-size: 1.25rem; }
.score-badge {
  display: inline-flex; align-items: center; gap: .55rem;
  padding: .35rem .8rem; border-radius: 999px; font-weight: 600;
  font-size: .9rem; border: 1px solid transparent;
}
.score-faible    { background: #052e2b; color: #34d399; border-color: #0f766e; }
.score-moyen     { background: #3b2f05; color: #fbbf24; border-color: #b45309; }
.score-élevé     { background: #450a0a; color: #f87171; border-color: #b91c1c; }
.score-critique  { background: #3b0764; color: #e879f9; border-color: #a21caf; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: .6rem 1.5rem; }
.kv { display: flex; justify-content: space-between; gap: 1rem; padding: .25rem 0; border-bottom: 1px dashed #1e293b; font-size: .9rem; }
.kv:last-child { border-bottom: 0; }
.kv .k { color: #94a3b8; }
.kv .v { color: #e2e8f0; text-align: right; word-break: break-word; max-width: 60%; }
.factors { list-style: none; padding: 0; margin: .5rem 0 0 0; }
.factors li { padding: .25rem 0; font-size: .9rem; }
.factors .name { color: #2dd4bf; font-family: monospace; }
.tags { display: flex; flex-wrap: wrap; gap: .35rem; margin-top: .3rem; }
.tag { background: #1e293b; color: #cbd5e1; padding: .15rem .55rem; border-radius: 6px; font-size: .78rem; }
.tag.danger { background: #4c0519; color: #fecdd3; }
.tag.warn { background: #422006; color: #fde68a; }
.tag.info { background: #0c2a4a; color: #bae6fd; }
.summary { list-style: none; padding: 0; }
.summary li { padding: .3rem 0 .3rem 1rem; border-left: 3px solid #0f766e; margin: .35rem 0; font-size: .92rem; }
.src-ok { color: #34d399; }
.src-ko { color: #f87171; }
.ports { font-family: monospace; color: #7dd3fc; }
.footer { color: #64748b; font-size: .82rem; margin-top: 2.5rem; text-align: center; }
.levels { display: flex; flex-wrap: wrap; gap: .4rem; }
code { background: #1e293b; padding: .1rem .35rem; border-radius: 4px; font-size: .85rem; }
"""


def _esc(v: Any) -> str:
    if v is None:
        return "—"
    return html.escape(str(v))


def _render_report(report: IPReport) -> str:
    n = report.normalized
    risk = report.risk
    ident = n.get("identity", {})
    loc = n.get("location", {})
    exp = n.get("exposure", {})
    thr = n.get("threats", {})
    rep = n.get("reputation", {})

    lvl_class = f"score-{risk.level}"

    factors_html = ""
    if risk.factors:
        items = "".join(
            f"<li><span class='name'>{_esc(f['name'])}</span> "
            f"<span style='color:#94a3b8'>(+{f['weight']})</span> — {_esc(f['detail'])}</li>"
            for f in risk.factors
        )
        factors_html = f"<ul class='factors'>{items}</ul>"
    else:
        factors_html = "<p style='color:#94a3b8;font-size:.9rem'>Aucun facteur de risque significatif.</p>"

    def row(k: str, v: Any) -> str:
        return f"<div class='kv'><span class='k'>{_esc(k)}</span><span class='v'>{_esc(v)}</span></div>"

    def tag_class(t: str) -> str:
        low = t.lower()
        if low in {"tor", "malware", "botnet", "c2", "scanner", "bruteforce", "compromised", "spam", "phishing"}:
            return "tag danger"
        if low in {"proxy", "vpn", "datacenter", "cloud", "hosting"}:
            return "tag warn"
        return "tag info"

    tags_html = "".join(f"<span class='{tag_class(t)}'>{_esc(t)}</span>" for t in (exp.get("tags") or []))

    ports_html = (
        "".join(f"<span class='tag info'>{p}</span>" for p in (exp.get("open_ports") or []))
        or "<span style='color:#64748b'>—</span>"
    )

    cves_html = ""
    if thr.get("cves"):
        cves_html = "<div class='tags'>" + "".join(
            f"<span class='tag danger'>{_esc(c)}</span>" for c in thr["cves"]
        ) + "</div>"
    else:
        cves_html = "<span style='color:#64748b'>Aucune CVE connue</span>"

    bl = rep.get("blacklists") or []
    bl_html = ""
    if bl:
        bl_html = "<div class='tags'>" + "".join(
            f"<span class='tag danger'>{_esc(b)}</span>" for b in bl
        ) + "</div>"
    else:
        bl_html = "<span style='color:#64748b'>Aucune</span>"

    sources_html = ""
    for name, res in report.sources.items():
        if res.ok:
            sources_html += (
                f"<div class='kv'><span class='k'>{_esc(name)}</span>"
                f"<span class='v'><span class='src-ok'>✓ OK</span> "
                f"<span style='color:#64748b'>{_esc(res.latency_ms)} ms</span></span></div>"
            )
        else:
            sources_html += (
                f"<div class='kv'><span class='k'>{_esc(name)}</span>"
                f"<span class='v'><span class='src-ko'>✗ {_esc(res.error)}</span></span></div>"
            )

    summary_html = "".join(f"<li>{_esc(s)}</li>" for s in report.summary)

    return f"""
    <section class="card">
      <div class="ip-title">
        <div>
          <div class="ip-address">{_esc(report.ip)}</div>
          <div class="meta">Analysé le {_esc(report.timestamp)}</div>
        </div>
        <div class="score-badge {lvl_class}">
          Risque&nbsp;: {risk.score}/100 — {_esc(risk.level.upper())}
        </div>
      </div>
      <h3 style="margin-top:1rem">Facteurs contributifs</h3>
      {factors_html}
    </section>

    <section class="card">
      <h3>Identité réseau</h3>
      <div class="grid">
        {row("Hostname", ident.get("hostname"))}
        {row("Reverse DNS", ident.get("reverse_dns"))}
        {row("ASN", ident.get("asn"))}
        {row("Organisation", ident.get("org"))}
        {row("FAI", ident.get("isp"))}
      </div>
    </section>

    <section class="card">
      <h3>Localisation</h3>
      <div class="grid">
        {row("Pays", loc.get("country"))}
        {row("Région", loc.get("region"))}
        {row("Ville", loc.get("city"))}
        {row("Code postal", loc.get("postal"))}
        {row("Latitude", loc.get("lat"))}
        {row("Longitude", loc.get("lon"))}
        {row("Fuseau horaire", loc.get("timezone"))}
      </div>
    </section>

    <section class="card">
      <h3>Exposition réseau</h3>
      <p style="color:#94a3b8;font-size:.85rem;margin:.2rem 0 .4rem 0">Ports ouverts</p>
      <div class="tags">{ports_html}</div>
      <p style="color:#94a3b8;font-size:.85rem;margin:1rem 0 .4rem 0">Tags Shodan</p>
      <div class="tags">{tags_html or "<span style='color:#64748b'>—</span>"}</div>
      <p style="color:#94a3b8;font-size:.85rem;margin:1rem 0 .4rem 0">Hostnames</p>
      <div style="font-family:monospace;font-size:.85rem">{_esc(", ".join(exp.get("hostnames") or []) or "—")}</div>
      <p style="color:#94a3b8;font-size:.85rem;margin:1rem 0 .4rem 0">CPE</p>
      <div style="font-family:monospace;font-size:.85rem">{_esc(", ".join(exp.get("cpes") or []) or "—")}</div>
    </section>

    <section class="card">
      <h3>Vulnérabilités (CVE)</h3>
      {cves_html}
    </section>

    <section class="card">
      <h3>Réputation</h3>
      <div class="grid">
        {row("Score de fraude", rep.get("fraud_score"))}
        {row("VPN", rep.get("vpn"))}
        {row("Proxy", rep.get("proxy"))}
        {row("Tor", rep.get("tor"))}
        {row("Datacenter", rep.get("datacenter"))}
        {row("Signalements d'abus", rep.get("abuse_reports"))}
      </div>
      <p style="color:#94a3b8;font-size:.85rem;margin:1rem 0 .4rem 0">Blacklists ({len(bl)})</p>
      {bl_html}
    </section>

    <section class="card">
      <h3>Statut des sources</h3>
      {sources_html}
    </section>

    <section class="card">
      <h3>Points clés à retenir</h3>
      <ul class="summary">{summary_html}</ul>
    </section>
    """


def write_html(reports: List[IPReport], path: str) -> None:
    cards = "\n".join(_render_report(r) for r in reports)
    doc = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>G-IPHunter — Rapport d'analyse IP</title>
  <style>{_CSS}</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <div class="brand">G-IPHunter</div>
        <h1>Rapport d'analyse OSINT &amp; Threat Intelligence</h1>
      </div>
      <div class="meta">{len(reports)} IP analysée(s)</div>
    </div>
    {cards}
    <div class="footer">
      Généré par G-IPHunter — Outil d'aide à la décision. Le score de risque est un
      indicateur, pas une preuve de malveillance.
    </div>
  </div>
</body>
</html>
"""
    Path(path).write_text(doc, encoding="utf-8")