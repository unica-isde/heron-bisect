"""Phishing indicators: each function returns the points one indicator adds."""

import re
from collections.abc import Callable

from heron.models import ParsedEmail

W_KEYWORD = 1
W_IP_LINK = 3
W_PUNYCODE_LINK = 3
W_BRAND_MISMATCH = 3
W_AUTH_FAIL = 2
W_REPLY_TO_MISMATCH = 2

BRANDS = ["paypal", "microsoft", "amazon"]

KEYWORDS = ["urgent", "verify", "suspended", "password", "expires", "act now",
            "congratulations", "winner", "claim", "immediately", "gift card"]

_IP_URL_RE = re.compile("https?://[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+")


def keyword_score(email: ParsedEmail) -> int:
    """One point for each pressure keyword found anywhere in the message."""
    return sum(W_KEYWORD for kw in KEYWORDS if kw in email.text)


def link_score(email: ParsedEmail) -> int:
    """Points for links to a bare IP address or to a punycode domain."""
    s = 0
    for url in email.links:
        if _IP_URL_RE.match(url):
            s = s + W_IP_LINK
        if "xn--" in url:
            s = s + W_PUNYCODE_LINK
    return s


def brand_score(email: ParsedEmail) -> int:
    """Points when the sender name claims a brand but the address is elsewhere."""
    low = email.sender.lower()
    return sum(W_BRAND_MISMATCH for brand in BRANDS
               if brand in low and brand + ".com" not in low)


def auth_score(email: ParsedEmail) -> int:
    """Points when SPF or DMARC failed."""
    if "spf=fail" in email.auth_results or "dmarc=fail" in email.auth_results:
        return W_AUTH_FAIL
    return 0


def reply_to_score(email: ParsedEmail) -> int:
    """Points when replies go to a different domain than the sender's."""
    from_domain, reply_domain = email.from_domain, email.reply_to_domain
    if from_domain and reply_domain and from_domain != reply_domain:
        return W_REPLY_TO_MISMATCH
    return 0


ALL_CHECKS: tuple[Callable[[ParsedEmail], int], ...] = (
    keyword_score,
    link_score,
    brand_score,
    auth_score,
    reply_to_score,
)
