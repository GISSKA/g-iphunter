"""Base class for OSINT sources."""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any

import requests

from g_iphunter.core.models import SourceResult


class Source(ABC):
    """Abstract OSINT source.

    Subclasses define `name` and `url_template`, and implement `query()`.
    The `fetch()` wrapper adds timing and error capture so a single failing
    source never breaks the whole analysis.
    """

    name: str = "base"
    url_template: str = ""

    def url_for(self, ip: str) -> str:
        return self.url_template.format(ip=ip)

    def fetch(
        self,
        ip: str,
        session: requests.Session,
        timeout: float = 10.0,
    ) -> SourceResult:
        url = self.url_for(ip)
        start = time.perf_counter()
        try:
            data = self.query(ip, session, timeout)
            latency = (time.perf_counter() - start) * 1000.0
            return SourceResult(
                source=self.name,
                ok=True,
                data=data,
                latency_ms=round(latency, 1),
                url=url,
            )
        except requests.Timeout as exc:
            latency = (time.perf_counter() - start) * 1000.0
            return SourceResult(
                source=self.name,
                ok=False,
                error=f"Timeout après {timeout}s",
                latency_ms=round(latency, 1),
                url=url,
            )
        except requests.HTTPError as exc:
            latency = (time.perf_counter() - start) * 1000.0
            status = exc.response.status_code if exc.response is not None else "?"
            return SourceResult(
                source=self.name,
                ok=False,
                error=f"HTTP {status}",
                latency_ms=round(latency, 1),
                url=url,
            )
        except requests.RequestException as exc:
            latency = (time.perf_counter() - start) * 1000.0
            return SourceResult(
                source=self.name,
                ok=False,
                error=f"Erreur réseau: {exc.__class__.__name__}",
                latency_ms=round(latency, 1),
                url=url,
            )
        except ValueError as exc:
            latency = (time.perf_counter() - start) * 1000.0
            return SourceResult(
                source=self.name,
                ok=False,
                error=f"Réponse invalide: {exc}",
                latency_ms=round(latency, 1),
                url=url,
            )
        except Exception as exc:  # noqa: BLE001 - last-resort guard
            latency = (time.perf_counter() - start) * 1000.0
            return SourceResult(
                source=self.name,
                ok=False,
                error=f"Erreur inattendue: {exc}",
                latency_ms=round(latency, 1),
                url=url,
            )

    @abstractmethod
    def query(self, ip: str, session: requests.Session, timeout: float) -> Any:
        """Perform the actual API call. Raise on failure."""