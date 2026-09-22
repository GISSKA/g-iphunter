"""IPinfo Legacy API — https://ipinfo.io/<IP>/json (no key required)."""
from __future__ import annotations

import requests

from g_iphunter.core.http import get_json
from g_iphunter.sources.base import Source


class IPinfoSource(Source):
    name = "ipinfo"
    url_template = "https://ipinfo.io/{ip}/json"

    def query(self, ip: str, session: requests.Session, timeout: float):
        return get_json(session, self.url_for(ip), timeout=timeout)