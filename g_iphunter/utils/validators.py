"""Input validation helpers."""
from __future__ import annotations

import ipaddress
from typing import Iterable, List


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def parse_ip_list(raw: Iterable[str]) -> List[str]:
    """Clean up a raw iterable of candidate IPs, dropping comments/empties."""
    cleaned: List[str] = []
    seen = set()
    for line in raw:
        token = line.strip()
        if not token or token.startswith("#"):
            continue
        # Allow "ip,comment" or "ip # comment" notations.
        token = token.split(",")[0].split("#")[0].strip()
        if not token:
            continue
        if not is_valid_ip(token):
            continue
        if token in seen:
            continue
        seen.add(token)
        cleaned.append(token)
    return cleaned