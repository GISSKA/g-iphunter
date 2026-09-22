"""Public OSINT sources queried by G-IPHunter."""
from g_iphunter.sources.ffraud import FFraudSource
from g_iphunter.sources.ipaddress_you import IPAddressYouSource
from g_iphunter.sources.ipaddress_you_blacklist import IPAddressYouBlacklistSource
from g_iphunter.sources.ipinfo import IPinfoSource
from g_iphunter.sources.shodan_internetdb import ShodanInternetDBSource

ALL_SOURCES = [
    IPinfoSource,
    ShodanInternetDBSource,
    FFraudSource,
    IPAddressYouSource,
    IPAddressYouBlacklistSource,
]

__all__ = [
    "ALL_SOURCES",
    "FFraudSource",
    "IPAddressYouSource",
    "IPAddressYouBlacklistSource",
    "IPinfoSource",
    "ShodanInternetDBSource",
]