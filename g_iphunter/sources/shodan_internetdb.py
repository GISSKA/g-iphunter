"""Shodan InternetDB — https://internetdb.shodan.io/<IP> (public, no key)."""
from __future__ import annotations

import requests

from g_iphunter.core.http import get_json
from g_iphunter.sources.base import Source


class ShodanInternetDBSource(Source):
    name = "shodan_internetdb"
    url_template = "https://internetdb.shodan.io/{ip}"

    def query(self, ip: str, session: requests.Session, timeout: float):
        # InternetDB returns 404 with {"detail": "No information available"}
        # for IPs without indexed data — treat that as an empty result.
        data = get_json(session, self.url_for(ip), timeout=timeout, allow_404=True)
        if isinstance(data, dict) and data.get("detail") == "No information available":
            return {
                "ports": [],
                "cpes": [],
                "hostnames": [],
                "tags": [],
                "vulns": [],
                "note": "Aucune donnée indexée par Shodan InternetDB",
            }
        return data