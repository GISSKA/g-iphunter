"""Normalize heterogeneous source payloads into a single IP view."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from g_iphunter.core.models import SourceResult


def _first(*values):
    for v in values:
        if v not in (None, "", [], {}):
            return v
    return None


def _to_bool(value) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("true", "yes", "1", "y"):
            return True
        if low in ("false", "no", "0", "n"):
            return False
    return None


def normalize(ip: str, sources: Dict[str, SourceResult]) -> Dict[str, Any]:
    """Merge all source payloads into a normalized structure."""
    n: Dict[str, Any] = {
        "identity": {
            "ip": ip,
            "hostname": None,
            "reverse_dns": None,
            "asn": None,
            "org": None,
            "isp": None,
        },
        "location": {
            "country": None,
            "region": None,
            "city": None,
            "postal": None,
            "lat": None,
            "lon": None,
            "timezone": None,
        },
        "exposure": {
            "open_ports": [],
            "cpes": [],
            "hostnames": [],
            "tags": [],
        },
        "threats": {"cves": [], "vulns": []},
        "reputation": {
            "fraud_score": None,
            "vpn": None,
            "proxy": None,
            "tor": None,
            "datacenter": None,
            "abuse_reports": None,
            "blacklists": [],
        },
    }

    # --- ipinfo -------------------------------------------------------------
    r = sources.get("ipinfo")
    if r and r.ok and isinstance(r.data, dict):
        d = r.data
        n["identity"]["hostname"] = _first(d.get("hostname"))
        org = d.get("org")
        if isinstance(org, str) and org.upper().startswith("AS"):
            parts = org.split(" ", 1)
            n["identity"]["asn"] = parts[0]
            n["identity"]["org"] = parts[1] if len(parts) > 1 else None
        else:
            n["identity"]["org"] = org
        n["location"]["country"] = _first(d.get("country"))
        n["location"]["region"] = _first(d.get("region"))
        n["location"]["city"] = _first(d.get("city"))
        n["location"]["postal"] = _first(d.get("postal"))
        n["location"]["timezone"] = _first(d.get("timezone"))
        loc = d.get("loc")
        if isinstance(loc, str) and "," in loc:
            try:
                lat, lon = loc.split(",", 1)
                n["location"]["lat"] = float(lat)
                n["location"]["lon"] = float(lon)
            except (TypeError, ValueError):
                pass

    # --- shodan internetdb --------------------------------------------------
    r = sources.get("shodan_internetdb")
    if r and r.ok and isinstance(r.data, dict):
        d = r.data
        n["exposure"]["open_ports"] = sorted(set(d.get("ports") or []))
        n["exposure"]["cpes"] = list(d.get("cpes") or [])
        n["exposure"]["hostnames"] = list(d.get("hostnames") or [])
        n["exposure"]["tags"] = list(d.get("tags") or [])
        vulns = list(d.get("vulns") or [])
        n["threats"]["cves"] = vulns
        n["threats"]["vulns"] = vulns

    # --- ffraud -------------------------------------------------------------
    r = sources.get("ffraud")
    if r and r.ok and isinstance(r.data, dict):
        d = r.data
        n["reputation"]["fraud_score"] = _first(
            d.get("fraud_score"), d.get("score"), d.get("risk_score")
        )
        n["reputation"]["vpn"] = _to_bool(_first(d.get("vpn"), d.get("is_vpn")))
        n["reputation"]["proxy"] = _to_bool(_first(d.get("proxy"), d.get("is_proxy")))
        n["reputation"]["tor"] = _to_bool(_first(d.get("tor"), d.get("is_tor")))
        n["reputation"]["datacenter"] = _to_bool(
            _first(d.get("datacenter"), d.get("is_datacenter"), d.get("hosting"))
        )
        abuse = _first(d.get("abuse_reports"), d.get("abuse"), d.get("abuse_count"))
        if isinstance(abuse, (int, float)):
            n["reputation"]["abuse_reports"] = int(abuse)

    # --- ipaddress.you ------------------------------------------------------
    r = sources.get("ipaddress_you")
    if r and r.ok and isinstance(r.data, dict):
        d = r.data
        if not n["identity"]["isp"]:
            n["identity"]["isp"] = _first(d.get("isp"), d.get("org"), d.get("organization"))
        if not n["identity"]["asn"]:
            asn = _first(d.get("asn"), d.get("as"))
            if isinstance(asn, int):
                asn = f"AS{asn}"
            n["identity"]["asn"] = asn
        if not n["identity"]["reverse_dns"]:
            n["identity"]["reverse_dns"] = _first(
                d.get("reverse"), d.get("reverse_dns"), d.get("hostname"), d.get("ptr")
            )
        if not n["location"]["country"]:
            n["location"]["country"] = _first(d.get("country"), d.get("country_code"))
        if not n["location"]["region"]:
            n["location"]["region"] = _first(d.get("region"), d.get("region_name"))
        if not n["location"]["city"]:
            n["location"]["city"] = _first(d.get("city"))
        if n["location"]["lat"] is None and d.get("latitude") is not None:
            try:
                n["location"]["lat"] = float(d["latitude"])
            except (TypeError, ValueError):
                pass
        if n["location"]["lon"] is None and d.get("longitude") is not None:
            try:
                n["location"]["lon"] = float(d["longitude"])
            except (TypeError, ValueError):
                pass

    # --- ipaddress.you blacklist -------------------------------------------
    r = sources.get("ipaddress_you_blacklist")
    if r and r.ok and r.data is not None:
        d = r.data
        bl: List[Any] = []
        if isinstance(d, list):
            bl = [str(x) for x in d]
        elif isinstance(d, dict):
            for key in ("lists", "blacklists", "blocklists", "sources"):
                if isinstance(d.get(key), list):
                    bl = [str(x) for x in d[key]]
                    break
            if not bl and d.get("blacklisted") and isinstance(d.get("result"), list):
                bl = [str(x) for x in d["result"]]
            if not bl and d.get("listed") is True:
                bl = ["(listé — détail non fourni)"]
        n["reputation"]["blacklists"] = sorted(set(bl))

    return n


def build_summary(normalized: Dict[str, Any], risk_score: int) -> List[str]:
    """Produce human-readable key observations for the report."""
    items: List[str] = []
    rep = normalized["reputation"]
    exp = normalized["exposure"]
    thr = normalized["threats"]

    if rep.get("tor"):
        items.append("Nœud de sortie Tor identifié — anonymisation forte.")
    if rep.get("proxy"):
        items.append("IP utilisée comme proxy public/ouvert.")
    if rep.get("vpn"):
        items.append("IP associée à un service VPN commercial.")
    if rep.get("datacenter"):
        items.append("IP hébergée dans un datacenter (usage serveur probable).")

    fs = rep.get("fraud_score")
    if isinstance(fs, (int, float)) and fs >= 50:
        items.append(f"Score de fraude élevé signalé par FFraud ({fs}).")

    abuse = rep.get("abuse_reports")
    if isinstance(abuse, int) and abuse > 0:
        items.append(f"{abuse} signalement(s) d'abus recensés.")

    bl = rep.get("blacklists") or []
    if bl:
        items.append(f"Présente sur {len(bl)} blacklist(s) / DNSBL.")

    cves = thr.get("cves") or []
    if cves:
        sample = ", ".join(cves[:5])
        suffix = "…" if len(cves) > 5 else ""
        items.append(f"{len(cves)} CVE associée(s) à des services exposés : {sample}{suffix}")

    ports = exp.get("open_ports") or []
    if ports:
        items.append(f"{len(ports)} port(s) ouvert(s) exposés publiquement : {ports}")

    tags = exp.get("tags") or []
    if tags:
        items.append(f"Tags Shodan : {', '.join(tags)}")

    if not items:
        items.append("Aucun indicateur fort détecté sur les sources consultées.")

    if risk_score >= 50:
        items.append(
            "⚠ Investigation humaine recommandée : plusieurs signaux corrélés."
        )
    items.append(
        "Rappel : ce score est un indicateur d'aide à l'analyse, il ne constitue "
        "pas une preuve de malveillance."
    )
    return items