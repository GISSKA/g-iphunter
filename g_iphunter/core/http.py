"""Shared HTTP session factory with retries and sane defaults."""
from __future__ import annotations

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

USER_AGENT = "G-IPHunter/1.0 (+https://github.com/GISSKA/g-iphunter)"


def make_session() -> requests.Session:
    """Return a requests.Session with retries and a proper User-Agent."""
    session = requests.Session()
    retry = Retry(
        total=2,
        connect=2,
        read=2,
        backoff_factor=0.4,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})
    return session


def get_json(
    session: requests.Session,
    url: str,
    timeout: float = 10.0,
    allow_404: bool = False,
):
    """GET url and return decoded JSON.

    If allow_404 is True, a 404 response body is decoded and returned instead of
    raising an HTTPError. This is used for APIs like Shodan InternetDB that
    signal 'no data' via 404 with a JSON body.
    """
    resp = session.get(url, timeout=timeout)
    if resp.status_code == 404 and allow_404:
        try:
            return resp.json()
        except ValueError:
            return {"detail": "not found"}
    resp.raise_for_status()
    if not resp.content:
        return {}
    try:
        return resp.json()
    except ValueError as exc:
        raise ValueError(f"Réponse non-JSON depuis {url}: {exc}") from exc