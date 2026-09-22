"""Data models used across the pipeline."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SourceResult:
    """Result returned by a single OSINT source."""

    source: str
    ok: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    latency_ms: Optional[float] = None
    url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RiskAssessment:
    score: int
    level: str
    factors: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"score": self.score, "level": self.level, "factors": self.factors}


@dataclass
class IPReport:
    """Full analysis report for a single IP address."""

    ip: str
    timestamp: str
    sources: Dict[str, SourceResult] = field(default_factory=dict)
    normalized: Dict[str, Any] = field(default_factory=dict)
    risk: RiskAssessment = field(default_factory=lambda: RiskAssessment(0, "faible", []))
    summary: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "timestamp": self.timestamp,
            "risk": self.risk.to_dict(),
            "sources": {k: v.to_dict() for k, v in self.sources.items()},
            "normalized": self.normalized,
            "summary": self.summary,
        }