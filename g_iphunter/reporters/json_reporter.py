"""Serialize reports to JSON."""
from __future__ import annotations

import json
from pathlib import Path
from typing import List

from g_iphunter.core.models import IPReport


def reports_to_dict(reports: List[IPReport]) -> dict:
    return {
        "tool": "G-IPHunter",
        "version": "1.0.0",
        "count": len(reports),
        "reports": [r.to_dict() for r in reports],
    }


def write_json(reports: List[IPReport], path: str) -> None:
    payload = reports_to_dict(reports)
    Path(path).write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )