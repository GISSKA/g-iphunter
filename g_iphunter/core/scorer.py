"""Heuristic risk scoring (0-100) — an analytic aid, not a verdict."""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from g_iphunter.core.models import RiskAssessment

# Ports that are commonly exposed in an insecure way.
RISKY_PORTS: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    135: "MS-RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

SUSPICIOUS_TAGS = {
    "malware",
    "botnet",
    "c2",
    "command-and-control",
    "scanner",
    "bruteforce",
    "brute-force",
    "honeypot",
    "compromised",
    "spam",
    "phishing",
    "exploit",
}


def _clamp(value: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, value))


def score_ip(normalized: Dict[str, Any]) -> RiskAssessment:
    factors: List[Tuple[str, int, str]] = []
    score = 0

    rep = normalized.get("reputation", {}) or {}
    exp = normalized.get("exposure", {}) or {}
    thr = normalized.get("threats", {}) or {}

    # --- Fraud score --------------------------------------------------------
    fs = rep.get("fraud_score")
    if isinstance(fs, (int, float)):
        if fs >= 75:
            score += 30
            factors.append(("fraud_score", 30, f"Score de fraude très élevé ({fs})"))
        elif fs >= 50:
            score += 18
            factors.append(("fraud_score", 18, f"Score de fraude élevé ({fs})"))
        elif fs >= 25:
            score += 8
            factors.append(("fraud_score", 8, f"Score de fraude modéré ({fs})"))

    # --- Anonymizers / hosting ---------------------------------------------
    if rep.get("tor"):
        score += 20
        factors.append(("tor", 20, "Nœud de sortie Tor détecté"))
    if rep.get("proxy"):
        score += 12
        factors.append(("proxy", 12, "Service proxy public détecté"))
    if rep.get("vpn"):
        score += 8
        factors.append(("vpn", 8, "Service VPN commercial détecté"))
    if rep.get("datacenter"):
        score += 5
        factors.append(("datacenter", 5, "IP hébergée en datacenter"))

    # --- Abuse reports ------------------------------------------------------
    abuse = rep.get("abuse_reports")
    if isinstance(abuse, int) and abuse > 0:
        add = min(20, abuse * 3)
        score += add
        factors.append(("abuse", add, f"{abuse} signalement(s) d'abus"))

    # --- Blacklists ---------------------------------------------------------
    bl = rep.get("blacklists") or []
    if bl:
        add = min(25, len(bl) * 5)
        score += add
        factors.append(("blacklists", add, f"Listé sur {len(bl)} blacklist(s)"))

    # --- CVEs ---------------------------------------------------------------
    cves = thr.get("cves") or []
    if cves:
        add = min(20, len(cves) * 4)
        score += add
        factors.append(("cves", add, f"{len(cves)} CVE associée(s)"))

    # --- Risky ports --------------------------------------------------------
    ports = set(exp.get("open_ports") or [])
    risky = sorted(p for p in ports if p in RISKY_PORTS)
    if risky:
        add = min(15, len(risky) * 3)
        score += add
        names = ", ".join(f"{p}/{RISKY_PORTS[p]}" for p in risky)
        factors.append(("risky_ports", add, f"Ports sensibles exposés : {names}"))

    # --- Suspicious tags ----------------------------------------------------
    tags = [str(t).lower() for t in (exp.get("tags") or [])]
    found = sorted(set(t for t in tags if t in SUSPICIOUS_TAGS))
    if found:
        add = min(15, len(found) * 5)
        score += add
        factors.append(("suspicious_tags", add, f"Tags suspects : {', '.join(found)}"))

    score = _clamp(score)
    if score >= 75:
        level = "critique"
    elif score >= 50:
        level = "élevé"
    elif score >= 25:
        level = "moyen"
    else:
        level = "faible"

    return RiskAssessment(
        score=score,
        level=level,
        factors=[{"name": n, "weight": w, "detail": d} for (n, w, d) in factors],
    )