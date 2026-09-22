"""FFraud Public IP API — https://api.ffraud.com/public/ip/<IP> (public)."""
from __future__ import annotations

import requests

from g_iphunter.core.http import get_json
from g_iphunter.sources.base import Source


class FFraudSource(Source):
    name = "ffraud"
    url_template = "https://api.ffraud.com/public/ip/{ip}"

    def query(self, ip: str, session: requests.Session, timeout: float):
        return get_json(session, self.url_for(ip), timeout=timeout)