""" Console output """


from __future__ import annotations

import ctypes
import os
import sys
from typing import Any, List

from g_iphunter.core.models import IPReport

# ---------------------------------------------------------------------------
# ANSI escape codes
# ---------------------------------------------------------------------------
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

COLORS = {
    "black":          "\033[30m",
    "red":            "\033[31m",
    "green":          "\033[32m",
    "yellow":         "\033[33m",
    "blue":           "\033[34m",
    "magenta":        "\033[35m",
    "cyan":           "\033[36m",
    "white":          "\033[37m",
    "gray":           "\033[90m",
    "bright_red":     "\033[91m",
    "bright_green":   "\033[92m",
    "bright_yellow":  "\033[93m",
    "bright_blue":    "\033[94m",
    "bright_magenta": "\033[95m",
    "bright_cyan":    "\033[96m",
    "bright_white":   "\033[97m",
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
BANNER_LINES = [
    " ██████╗       ██╗██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ ",
    "██╔════╝       ██║██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗",
    "██║  ███╗█████╗██║██████╔╝███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝",
    "██║   ██║╚════╝██║██╔═══╝ ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗",
    "╚██████╔╝      ██║██║     ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║",
    " ╚═════╝       ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝",
]
BANNER_PALETTE = ["bright_cyan", "cyan", "bright_blue", "cyan", "bright_cyan", "cyan"]
TAGLINE = "OSINT · THREAT INTELLIGENCE · IP ANALYSIS"

LEVEL_COLORS = {
    "faible":   "bright_green",
    "moyen":    "bright_yellow",
    "élevé":    "bright_red",
    "critique": "bright_magenta",
}

LEVEL_ICONS = {
    "faible":   "●",
    "moyen":    "▲",
    "élevé":    "▲",
    "critique": "◆",
}


# ---------------------------------------------------------------------------
# Windows ANSI activation
# ---------------------------------------------------------------------------
_ANSI_ENABLED = False


def enable_ansi_colors() -> bool:
    """Active le traitement des séquences ANSI/VT sur Windows 10+.

    Retourne True si les couleurs sont utilisables, False sinon.
    Sans cet appel, cmd.exe affiche les codes d'échappement en clair.
    """
    global _ANSI_ENABLED
    if _ANSI_ENABLED:
        return True

    if os.name != "nt":
        _ANSI_ENABLED = True
        return True

    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            # 0x0004 = ENABLE_VIRTUAL_TERMINAL_PROCESSING
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
            _ANSI_ENABLED = True
            return True
    except Exception:
        pass

    # Fallback : essayer via colorama si présent
    try:
        import colorama  # type: ignore
        colorama.just_fix_windows_console()
        _ANSI_ENABLED = True
        return True
    except Exception:
        _ANSI_ENABLED = False
        return False


def _color(text: str, color: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{COLORS.get(color, '')}{text}{RESET}"


def _bold(text: str, use_color: bool) -> str:
    return f"{BOLD}{text}{RESET}" if use_color else text


def _dim(text: str, use_color: bool) -> str:
    return f"{DIM}{text}{RESET}" if use_color else text


def _rule(char: str = "─", width: int = 78, use_color: bool = True,
          color: str = "gray") -> str:
    return _color(char * width, color, use_color)


# ---------------------------------------------------------------------------
# Banner + step logs (appelés par le CLI)
# ---------------------------------------------------------------------------
def print_banner(use_color: bool = True) -> None:
    """Affiche le banner G-IPHunter avec effet dégradé."""
    if use_color:
        enable_ansi_colors()

    width = max(len(line) for line in BANNER_LINES)
    print()
    for i, line in enumerate(BANNER_LINES):
        print(_color(line, BANNER_PALETTE[i % len(BANNER_PALETTE)], use_color))
    print(_color(TAGLINE.center(width), "bright_yellow", use_color))
    print()


def log_step(label: str, message: str, color: str = "bright_cyan",
             use_color: bool = True) -> None:
    """Affiche une ligne de log style `[TAG]    message`."""
    tag = f"[{label}]"
    padded = tag.ljust(10)
    print(f"{_color(padded, color, use_color)} {message}")


def log_ok(label: str, message: str, use_color: bool = True) -> None:
    log_step(label, message, color="bright_green", use_color=use_color)


def log_warn(label: str, message: str, use_color: bool = True) -> None:
    log_step(label, message, color="bright_yellow", use_color=use_color)


def log_error(label: str, message: str, use_color: bool = True) -> None:
    log_step(label, message, color="bright_red", use_color=use_color)


# ---------------------------------------------------------------------------
# Spinner de progression (threadé, non bloquant)
# ---------------------------------------------------------------------------
def spinner(stop_event, message: str = "Analyse en cours",
            use_color: bool = True) -> None:
    """Affiche un spinner jusqu'à ce que stop_event soit positionné."""
    import time

    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    palette = ["bright_cyan", "cyan", "bright_blue"]
    i = 0
    while not stop_event.is_set():
        frame = frames[i % len(frames)]
        color = palette[i % len(palette)]
        line = f"  {_color(frame, color, use_color)} {message}…"
        sys.stdout.write("\r" + line)
        sys.stdout.flush()
        time.sleep(0.08)
        i += 1
    # Effacer la ligne
    sys.stdout.write("\r" + " " * (len(message) + 12) + "\r")
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# Rendu du rapport d'une IP
# ---------------------------------------------------------------------------
def _kv(label: str, value: Any, use_color: bool, width_label: int = 18) -> str:
    label_str = label.ljust(width_label, ".")
    if value in (None, "", [], {}):
        val_str = "—"
    else:
        val_str = str(value)
    return f"    {_dim(label_str, use_color)} {val_str}"


def _section(title: str, use_color: bool) -> str:
    return f"\n  {_color('▌', 'bright_cyan', use_color)} {_bold(title, use_color)}"


def render_report(report: IPReport, use_color: bool = True) -> str:
    """Rend un IPReport en texte colorisé (ou brut si use_color=False)."""
    if use_color:
        enable_ansi_colors()

    n = report.normalized or {}
    risk = report.risk
    ident = n.get("identity", {}) or {}
    loc = n.get("location", {}) or {}
    exp = n.get("exposure", {}) or {}
    thr = n.get("threats", {}) or {}
    rep = n.get("reputation", {}) or {}

    lvl_color = LEVEL_COLORS.get(risk.level, "bright_yellow")
    lvl_icon = LEVEL_ICONS.get(risk.level, "●")

    lines: List[str] = []

    # --- En-tête ------------------------------------------------------------
    lines.append("")
    lines.append(_rule("═", use_color=use_color, color="bright_cyan"))
    title_left = f"  {_bold('RAPPORT · ' + report.ip, use_color)}"
    lines.append(f"{title_left}")
    lines.append(f"  {_dim(report.timestamp, use_color)}")
    lines.append(_rule("═", use_color=use_color, color="bright_cyan"))

    # --- Score de risque ----------------------------------------------------
    bar_len = 34
    filled = int(round((risk.score / 100) * bar_len))
    bar = "█" * filled + "░" * (bar_len - filled)
    bar_colored = _color(bar, lvl_color, use_color)

    lines.append("")
    lines.append(_section("SCORE DE RISQUE", use_color))
    lines.append(
        f"    {bar_colored}  "
        f"{_color(f'{risk.score}/100', lvl_color, use_color)}  "
        f"{_color(f'[{lvl_icon} {risk.level.upper()}]', lvl_color, use_color)}"
    )

    if risk.factors:
        lines.append("")
        for factor in risk.factors:
            name = factor.get("name", "")
            weight = factor.get("weight", 0)
            detail = factor.get("detail", "")
            bullet = _color("▸", "bright_cyan", use_color)
            name_str = _bold(name, use_color)
            weight_str = _dim(f"(+{weight})", use_color)
            lines.append(f"    {bullet} {name_str} {weight_str}  {detail}")
    else:
        lines.append("    " + _dim("Aucun facteur de risque significatif.", use_color))

    # --- Identité réseau ----------------------------------------------------
    lines.append(_section("IDENTITÉ RÉSEAU", use_color))
    lines.append(_kv("Hostname", ident.get("hostname"), use_color))
    lines.append(_kv("Reverse DNS", ident.get("reverse_dns"), use_color))
    lines.append(_kv("ASN", ident.get("asn"), use_color))
    lines.append(_kv("Organisation", ident.get("org"), use_color))
    lines.append(_kv("FAI", ident.get("isp"), use_color))

    # --- Localisation -------------------------------------------------------
    if any(v for v in loc.values() if v not in (None, "", [], {})):
        lines.append(_section("LOCALISATION", use_color))
        country = loc.get("country")
        region = loc.get("region")
        city = loc.get("city")
        place = " / ".join(x for x in (country, region, city) if x) or None
        lines.append(_kv("Lieu", place, use_color))
        if loc.get("lat") is not None and loc.get("lon") is not None:
            lines.append(_kv("Coordonnées", f"{loc['lat']}, {loc['lon']}", use_color))
        if loc.get("timezone"):
            lines.append(_kv("Fuseau horaire", loc.get("timezone"), use_color))

    # --- Exposition réseau --------------------------------------------------
    lines.append(_section("EXPOSITION RÉSEAU", use_color))
    ports = exp.get("open_ports") or []
    ports_str = ", ".join(str(p) for p in ports) if ports else None
    lines.append(_kv("Ports ouverts", ports_str, use_color))
    if exp.get("hostnames"):
        lines.append(_kv("Hostnames", ", ".join(exp["hostnames"][:8]), use_color))
    if exp.get("cpes"):
        lines.append(_kv("CPE", ", ".join(exp["cpes"][:6]), use_color))
    if exp.get("tags"):
        lines.append(_kv("Tags", ", ".join(exp["tags"]), use_color))

    # --- Vulnérabilités -----------------------------------------------------
    cves = thr.get("cves") or []
    if cves:
        lines.append(_section("VULNÉRABILITÉS (CVE)", use_color))
        for cve in cves[:20]:
            lines.append(f"    {_color('•', 'bright_red', use_color)} {cve}")
        if len(cves) > 20:
            lines.append(_dim(f"    … {len(cves) - 20} de plus", use_color))

    # --- Réputation ---------------------------------------------------------
    lines.append(_section("RÉPUTATION", use_color))
    lines.append(_kv("Score de fraude", rep.get("fraud_score"), use_color))
    vpt = f"{rep.get('vpn')} / {rep.get('proxy')} / {rep.get('tor')}"
    lines.append(_kv("VPN / Proxy / Tor", vpt, use_color))
    lines.append(_kv("Datacenter", rep.get("datacenter"), use_color))
    lines.append(_kv("Signalements abus", rep.get("abuse_reports"), use_color))
    bl = rep.get("blacklists") or []
    if bl:
        bl_str = f"{len(bl)} entrée(s) — {', '.join(bl[:6])}"
    else:
        bl_str = "Aucune"
    lines.append(_kv("Blacklists", bl_str, use_color))

    # --- Statut des sources -------------------------------------------------
    lines.append(_section("STATUT DES SOURCES", use_color))
    for name, res in report.sources.items():
        if res.ok:
            marker = _color("✓", "bright_green", use_color)
            latency = _dim(f"{res.latency_ms} ms", use_color)
            lines.append(f"    {marker} {name:<26} {latency}")
        else:
            marker = _color("✗", "bright_red", use_color)
            err = _color(res.error or "erreur", "bright_red", use_color)
            lines.append(f"    {marker} {name:<26} {err}")

    # --- Points clés --------------------------------------------------------
    lines.append(_section("POINTS CLÉS", use_color))
    for item in report.summary:
        bullet = _color("▸", "bright_cyan", use_color)
        lines.append(f"    {bullet} {item}")

    lines.append("")
    lines.append(_rule("═", use_color=use_color, color="bright_cyan"))
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Résumé de l'analyse en lot
# ---------------------------------------------------------------------------
def render_batch_summary(reports: List[IPReport], use_color: bool = True) -> str:
    if use_color:
        enable_ansi_colors()

    lines: List[str] = []
    lines.append("")
    lines.append(_rule("═", use_color=use_color, color="bright_cyan"))
    lines.append(f"  {_bold('RÉSUMÉ · ANALYSE EN LOT', use_color)}")
    lines.append(_rule("═", use_color=use_color, color="bright_cyan"))
    lines.append("")

    ranked = sorted(reports, key=lambda r: r.risk.score, reverse=True)

    lines.append(_section("CLASSEMENT PAR SCORE DE RISQUE", use_color))
    for r in ranked:
        lvl_color = LEVEL_COLORS.get(r.risk.level, "bright_yellow")
        lvl_icon = LEVEL_ICONS.get(r.risk.level, "●")
        score_str = _color(f"{r.risk.score:>3}/100", lvl_color, use_color)
        level_str = _color(f"[{lvl_icon} {r.risk.level.upper()}]", lvl_color, use_color)
        lines.append(f"    {score_str}  {level_str:<24} {r.ip}")

    highs = [r for r in ranked if r.risk.score >= 50]
    if highs:
        lines.append("")
        lines.append(_section("NÉCESSITE UNE INVESTIGATION HUMAINE", use_color))
        for r in highs:
            reasons = "; ".join(f["detail"] for f in r.risk.factors[:3])
            bullet = _color("▸", "bright_red", use_color)
            lines.append(f"    {bullet} {_bold(r.ip, use_color)} — {reasons}")

    lines.append("")
    lines.append(_dim(
        "  Rappel : ces scores sont indicatifs et doivent être corroborés par "
        "une analyse contextuelle.",
        use_color,
    ))
    lines.append(_rule("═", use_color=use_color, color="bright_cyan"))
    lines.append("")
    return "\n".join(lines)