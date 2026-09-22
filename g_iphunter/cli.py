"""G-IPHunter CLI — orchestrates sources, scoring and reporters."""
from __future__ import annotations

import argparse
import sys
import threading
from pathlib import Path
from typing import List

from g_iphunter import __version__
from g_iphunter.core.orchestrator import Orchestrator
from g_iphunter.reporters.console import (
    enable_ansi_colors,
    log_error,
    log_ok,
    log_step,
    log_warn,
    print_banner,
    render_batch_summary,
    render_report,
    spinner,
)
from g_iphunter.reporters.html_reporter import write_html
from g_iphunter.reporters.json_reporter import write_json
from g_iphunter.reporters.pdf_reporter import write_pdf
from g_iphunter.sources import ALL_SOURCES
from g_iphunter.utils.validators import parse_ip_list


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="g-iphunter",
        description=(
            "G-IPHunter — Orchestrateur OSINT/Threat Intelligence pour analystes "
            "cybersécurité. Interroge plusieurs sources publiques, corrèle les "
            "résultats et produit un rapport JSON/HTML/PDF."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemples :\n"
            "  g-iphunter 8.8.8.8\n"
            "  g-iphunter 1.1.1.1 8.8.8.8 9.9.9.9\n"
            "  g-iphunter --file ips.txt --html report.html --pdf report.pdf --json report.json\n"
            "  g-iphunter 8.8.8.8 --timeout 5 --no-color\n"
        ),
    )
    p.add_argument("ips", nargs="*", help="Adresses IP à analyser (une ou plusieurs).")
    p.add_argument("-f", "--file", help="Fichier texte (une IP par ligne, '#' pour commenter).")
    p.add_argument("--json", dest="json_out", help="Chemin de sortie du rapport JSON.")
    p.add_argument("--html", dest="html_out", help="Chemin de sortie du rapport HTML.")
    p.add_argument("--pdf", dest="pdf_out", help="Chemin de sortie du rapport PDF.")
    p.add_argument("--timeout", type=float, default=10.0, help="Timeout HTTP par source (s). Défaut : 10.")
    p.add_argument("--concurrency", type=int, default=5, help="Nombre d'IP analysées en parallèle. Défaut : 5.")
    p.add_argument("--no-color", action="store_true", help="Désactiver la coloration ANSI.")
    p.add_argument("-q", "--quiet", action="store_true", help="Ne pas afficher le rapport console détaillé.")
    p.add_argument("-v", "--verbose", action="store_true", help="Afficher la progression sur stderr.")
    p.add_argument("--version", action="version", version=f"G-IPHunter {__version__}")
    return p


def _collect_ips(args) -> List[str]:
    raw: List[str] = list(args.ips)
    if args.file:
        path = Path(args.file)
        if not path.exists():
            raise FileNotFoundError(f"Fichier introuvable : {path}")
        raw.extend(path.read_text(encoding="utf-8").splitlines())
    return parse_ip_list(raw)


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # --- Détection couleur ---------------------------------------------------
    use_color = (not args.no_color) and sys.stdout.isatty()
    if use_color:
        enable_ansi_colors()

    # --- Collecte des IP -----------------------------------------------------
    try:
        ips = _collect_ips(args)
    except FileNotFoundError as exc:
        log_error("ERROR", str(exc), use_color=use_color)
        return 2

    # --- Cas "aucune IP" : help + banner -------------------------------------
    if not ips:
        if not args.quiet:
            print_banner(use_color=use_color)
        parser.print_help()
        return 0

    # --- Banner + logs d'initialisation --------------------------------------
    if not args.quiet:
        print_banner(use_color=use_color)

    log_step("INIT", f"G-IPHunter v{__version__}", color="bright_cyan", use_color=use_color)

    if len(ips) == 1:
        log_step("TARGET", ips[0], color="bright_cyan", use_color=use_color)
        log_step("MODE", "Analyse d'une IP unique", color="blue", use_color=use_color)
    else:
        log_step("TARGET", f"{len(ips)} adresses IP", color="bright_cyan", use_color=use_color)
        log_step("MODE", f"Analyse en lot (concurrency={args.concurrency})",
                 color="blue", use_color=use_color)

    log_step("TIMEOUT", f"{args.timeout}s par source", color="blue", use_color=use_color)

    # Sortie de secours en cas d'interruption clavier
    stop_event = threading.Event()

    # --- Analyse -------------------------------------------------------------
    orchestrator = Orchestrator(ALL_SOURCES, timeout=args.timeout)
    log_step("SCAN", f"Interrogation de {len(ALL_SOURCES)} sources en parallèle…",
             color="bright_magenta", use_color=use_color)

    if not args.quiet:
        worker = threading.Thread(
            target=spinner,
            args=(stop_event, f"Analyse de {len(ips)} IP"),
            kwargs={"use_color": use_color},
            daemon=True,
        )
        worker.start()
    else:
        worker = None

    try:
        reports = orchestrator.analyze_many(
            ips,
            max_workers=max(1, args.concurrency),
            progress=None,
        )
    except KeyboardInterrupt:
        stop_event.set()
        if worker:
            worker.join(timeout=1)
        log_warn("ABORT", "Interrompu par l'utilisateur.", use_color=use_color)
        return 130
    finally:
        stop_event.set()
        if worker:
            worker.join(timeout=1)

    # --- Bilan des sources ---------------------------------------------------
    total_sources = 0
    ok_sources = 0
    for r in reports:
        for src in r.sources.values():
            total_sources += 1
            if src.ok:
                ok_sources += 1

    if total_sources:
        pct = int(round(100 * ok_sources / total_sources))
        if pct == 100:
            log_ok("SOURCES", f"{ok_sources}/{total_sources} sources OK ({pct}%)",
                   use_color=use_color)
        elif pct >= 60:
            log_warn("SOURCES", f"{ok_sources}/{total_sources} sources OK ({pct}%) — "
                                f"certaines indisponibles",
                     use_color=use_color)
        else:
            log_error("SOURCES", f"{ok_sources}/{total_sources} sources OK ({pct}%) — "
                                 f"réseau dégradé",
                      use_color=use_color)

    # --- Résumé des scores ---------------------------------------------------
    for r in reports:
        color = "bright_green"
        if r.risk.score >= 75:
            color = "bright_magenta"
        elif r.risk.score >= 50:
            color = "bright_red"
        elif r.risk.score >= 25:
            color = "bright_yellow"
        log_step(
            "SCORE",
            f"{r.ip} — {r.risk.score}/100 [{r.risk.level.upper()}]",
            color=color,
            use_color=use_color,
        )

    # --- Rendu console -------------------------------------------------------
    if not args.quiet:
        print()
        for r in reports:
            print(render_report(r, use_color=use_color))
        if len(reports) > 1:
            print(render_batch_summary(reports, use_color=use_color))

    # --- Exports fichiers ----------------------------------------------------
    if args.json_out:
        write_json(reports, args.json_out)
        log_ok("JSON", args.json_out, use_color=use_color)
    if args.html_out:
        write_html(reports, args.html_out)
        log_ok("HTML", args.html_out, use_color=use_color)
    if args.pdf_out:
        write_pdf(reports, args.pdf_out)
        log_ok("PDF", args.pdf_out, use_color=use_color)

    log_ok("DONE", f"Analyse terminée — {len(reports)} IP traitée(s)",
           use_color=use_color)

    # --- Exit code -----------------------------------------------------------
    if any(r.risk.score >= 50 for r in reports):
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())