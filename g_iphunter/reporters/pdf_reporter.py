"""Professional PDF report using reportlab (Platypus)."""
from __future__ import annotations

from pathlib import Path
from typing import Any, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from g_iphunter.core.models import IPReport

PRIMARY = colors.HexColor("#0f766e")
DARK = colors.HexColor("#0f172a")
MUTED = colors.HexColor("#64748b")
LEVEL_COLORS = {
    "faible": colors.HexColor("#16a34a"),
    "moyen": colors.HexColor("#d97706"),
    "élevé": colors.HexColor("#dc2626"),
    "critique": colors.HexColor("#a21caf"),
}


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("H1", parent=ss["Title"], textColor=PRIMARY, fontSize=22, spaceAfter=6))
    ss.add(ParagraphStyle("H2", parent=ss["Heading2"], textColor=DARK, fontSize=14, spaceBefore=14, spaceAfter=6))
    ss.add(ParagraphStyle("H3", parent=ss["Heading3"], textColor=DARK, fontSize=11, spaceBefore=8, spaceAfter=4))
    ss.add(ParagraphStyle("Body", parent=ss["BodyText"], fontSize=9.5, leading=13))
    ss.add(ParagraphStyle("Muted", parent=ss["BodyText"], fontSize=8.5, textColor=MUTED))
    ss.add(ParagraphStyle("KV", parent=ss["BodyText"], fontSize=9.5))
    return ss


def _kv_table(rows: List[tuple], col_widths=(5 * cm, 11 * cm)) -> Table:
    data = [[Paragraph(f"<b>{k}</b>", _styles()["KV"]), Paragraph(str(v), _styles()["KV"])] for k, v in rows]
    table = Table(data, colWidths=col_widths, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("LINEBELOW", (0, 0), (-1, -2), 0.25, colors.HexColor("#e2e8f0")),
                ("TEXTCOLOR", (0, 0), (0, -1), MUTED),
            ]
        )
    )
    return table


def _esc(value: Any) -> str:
    if value is None or value == "":
        return "—"
    s = str(value)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _build_ip_story(report: IPReport, ss) -> list:
    story: list = []
    n = report.normalized
    risk = report.risk
    ident = n.get("identity", {})
    loc = n.get("location", {})
    exp = n.get("exposure", {})
    thr = n.get("threats", {})
    rep = n.get("reputation", {})

    story.append(Paragraph(f"IP : {_esc(report.ip)}", ss["H1"]))
    story.append(Paragraph(f"Horodatage (UTC) : {_esc(report.timestamp)}", ss["Muted"]))
    story.append(Spacer(1, 6))

    lvl_color = LEVEL_COLORS.get(risk.level, colors.orange)
    score_tbl = Table(
        [[
            Paragraph(
                f"<font color='white'><b>Score de risque : {risk.score}/100 — "
                f"{_esc(risk.level.upper())}</b></font>",
                ParagraphStyle("x", parent=ss["Body"], fontSize=12),
            )
        ]],
        colWidths=[16 * cm],
    )
    score_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), lvl_color),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(score_tbl)

    # Factors
    story.append(Paragraph("Facteurs contributifs", ss["H2"]))
    if risk.factors:
        for f in risk.factors:
            story.append(Paragraph(
                f"• <b>{_esc(f['name'])}</b> (+{f['weight']}) — {_esc(f['detail'])}",
                ss["Body"],
            ))
    else:
        story.append(Paragraph("Aucun facteur de risque significatif.", ss["Muted"]))

    # Identity
    story.append(Paragraph("Identité réseau", ss["H2"]))
    story.append(_kv_table([
        ("Hostname", _esc(ident.get("hostname"))),
        ("Reverse DNS", _esc(ident.get("reverse_dns"))),
        ("ASN", _esc(ident.get("asn"))),
        ("Organisation", _esc(ident.get("org"))),
        ("FAI", _esc(ident.get("isp"))),
    ]))

    # Location
    story.append(Paragraph("Localisation", ss["H2"]))
    story.append(_kv_table([
        ("Pays", _esc(loc.get("country"))),
        ("Région", _esc(loc.get("region"))),
        ("Ville", _esc(loc.get("city"))),
        ("Coordonnées", f"{_esc(loc.get('lat'))}, {_esc(loc.get('lon'))}"),
        ("Fuseau horaire", _esc(loc.get("timezone"))),
    ]))

    # Exposure
    story.append(Paragraph("Exposition réseau", ss["H2"]))
    ports = exp.get("open_ports") or []
    story.append(Paragraph(
        f"<b>Ports ouverts :</b> {_esc(', '.join(map(str, ports))) if ports else '—'}",
        ss["Body"],
    ))
    story.append(Paragraph(
        f"<b>Tags :</b> {_esc(', '.join(exp.get('tags') or [])) or '—'}",
        ss["Body"],
    ))
    story.append(Paragraph(
        f"<b>Hostnames :</b> {_esc(', '.join(exp.get('hostnames') or [])) or '—'}",
        ss["Body"],
    ))
    story.append(Paragraph(
        f"<b>CPE :</b> {_esc(', '.join(exp.get('cpes') or [])) or '—'}",
        ss["Body"],
    ))

    # Threats
    story.append(Paragraph("Vulnérabilités (CVE)", ss["H2"]))
    cves = thr.get("cves") or []
    if cves:
        for cve in cves:
            story.append(Paragraph(f"• {_esc(cve)}", ss["Body"]))
    else:
        story.append(Paragraph("Aucune CVE connue pour les services exposés.", ss["Muted"]))

    # Reputation
    story.append(Paragraph("Réputation", ss["H2"]))
    story.append(_kv_table([
        ("Score de fraude", _esc(rep.get("fraud_score"))),
        ("VPN", _esc(rep.get("vpn"))),
        ("Proxy", _esc(rep.get("proxy"))),
        ("Tor", _esc(rep.get("tor"))),
        ("Datacenter", _esc(rep.get("datacenter"))),
        ("Signalements d'abus", _esc(rep.get("abuse_reports"))),
        ("Blacklists", ", ".join(rep.get("blacklists") or []) or "Aucune"),
    ]))

    # Sources status
    story.append(Paragraph("Statut des sources", ss["H2"]))
    status_rows = []
    for name, res in report.sources.items():
        if res.ok:
            status_rows.append((name, f"OK ({res.latency_ms} ms)"))
        else:
            status_rows.append((name, f"ÉCHEC — {res.error}"))
    story.append(_kv_table(status_rows))

    # Summary
    story.append(Paragraph("Points clés", ss["H2"]))
    for item in report.summary:
        story.append(Paragraph(f"• {_esc(item)}", ss["Body"]))

    return story


def write_pdf(reports: List[IPReport], path: str) -> None:
    ss = _styles()
    doc = SimpleDocTemplate(
        path,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title="G-IPHunter Report",
        author="G-IPHunter",
    )

    story: list = []
    story.append(Paragraph("G-IPHunter", ParagraphStyle(
        "brand", parent=ss["Title"], textColor=PRIMARY, fontSize=26, spaceAfter=0
    )))
    story.append(Paragraph(
        "Rapport d'analyse OSINT &amp; Threat Intelligence",
        ParagraphStyle("sub", parent=ss["Title"], fontSize=14, textColor=MUTED, spaceAfter=16),
    ))
    story.append(Paragraph(
        f"{len(reports)} IP analysée(s) — rapport généré automatiquement à partir de "
        "sources publiques (IPinfo, Shodan InternetDB, FFraud, ipaddress.you).",
        ss["Body"],
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "<i>Avertissement : le score de risque est un indicateur d'aide à l'analyse. "
        "Il ne constitue pas une preuve de malveillance et doit être corroboré par "
        "d'autres éléments de contexte.</i>",
        ss["Muted"],
    ))
    story.append(PageBreak())

    for i, report in enumerate(reports):
        story.extend(_build_ip_story(report, ss))
        if i < len(reports) - 1:
            story.append(PageBreak())

    doc.build(story)