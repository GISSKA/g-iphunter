"""ipaddress.you — https://ipaddress.you/api/ip/<IP> (public)."""
from __future__ import annotations

import requests

from g_iphunter.core.http import get_json
from g_iphunter.sources.base import Source


class IPAddressYouSource(Source):
    name = "ipaddress_you"
    url_template = "https://ipaddress.you/api/ip/{ip}"

    def query(self, ip: str, session: requests.Session, timeout: float):
        return get_json(session, self.url_for(ip), timeout=timeout)