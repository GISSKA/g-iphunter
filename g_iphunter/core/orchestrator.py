"""Orchestrate sources, normalization and scoring for one or many IPs."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Iterable, List, Sequence, Type

import requests

from g_iphunter.core.aggregator import build_summary, normalize
from g_iphunter.core.http import make_session
from g_iphunter.core.models import IPReport, SourceResult
from g_iphunter.core.scorer import score_ip
from g_iphunter.sources.base import Source


class Orchestrator:
    """Query sources concurrently and assemble a full IPReport."""

    def __init__(
        self,
        source_classes: Sequence[Type[Source]],
        timeout: float = 10.0,
        per_ip_workers: int = 5,
    ) -> None:
        self.sources: List[Source] = [cls() for cls in source_classes]
        self.timeout = timeout
        self.per_ip_workers = per_ip_workers
        self._session: requests.Session = make_session()

    # ------------------------------------------------------------------ API
    def analyze(self, ip: str) -> IPReport:
        results = self._query_all_sources(ip)
        normalized = normalize(ip, results)
        risk = score_ip(normalized)
        summary = build_summary(normalized, risk.score)
        return IPReport(
            ip=ip,
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            sources=results,
            normalized=normalized,
            risk=risk,
            summary=summary,
        )

    def analyze_many(
        self,
        ips: Iterable[str],
        max_workers: int = 5,
        progress=None,
    ) -> List[IPReport]:
        ips = list(ips)
        reports: List[IPReport] = []
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(self.analyze, ip): ip for ip in ips}
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    reports.append(fut.result())
                except Exception as exc:  # noqa: BLE001
                    reports.append(
                        IPReport(
                            ip=ip,
                            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                            sources={},
                            normalized={},
                            summary=[f"Échec de l'analyse : {exc}"],
                        )
                    )
                if progress:
                    progress(ip)
        # Preserve input order for readability.
        order = {ip: i for i, ip in enumerate(ips)}
        reports.sort(key=lambda r: order.get(r.ip, 0))
        return reports

    # ------------------------------------------------------------------ internals
    def _query_all_sources(self, ip: str) -> dict:
        results: dict = {}
        with ThreadPoolExecutor(max_workers=self.per_ip_workers) as ex:
            futures = {
                ex.submit(src.fetch, ip, self._session, self.timeout): src.name
                for src in self.sources
            }
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    results[name] = fut.result()
                except Exception as exc:  # noqa: BLE001
                    results[name] = SourceResult(
                        source=name, ok=False, error=f"Erreur orchestrateur : {exc}"
                    )
        return results