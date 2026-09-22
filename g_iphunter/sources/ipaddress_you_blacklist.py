"""ipaddress.you Blacklist API — https://ipaddress.you/api/blacklist/<IP>."""
from __future__ import annotations

import requests

from g_iphunter.core.http import get_json
from g_iphunter.sources.base import Source


class IPAddressYouBlacklistSource(Source):
    name = "ipaddress_you_blacklist"
    url_template = "https://ipaddress.you/api/blacklist/{ip}"

    def query(self, ip: str, session: requests.Session, timeout: float):
        return get_json(session, self.url_for(ip), timeout=timeout)