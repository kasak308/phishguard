"""Turns a URL string into the 15 numeric features PhishGuard learns from."""
import math
import re
from urllib.parse import urlparse

BAIT_WORDS = ["secure", "verify", "update", "confirm", "login", "account",
              "signin", "webscr", "recovery", "alert", "billing", "wallet",
              "suspended", "password"]
RISKY_TLDS = (".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz", ".click")
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# The last three features were added after Google Gemini reviewed the first
# twelve and pointed out that domain entropy, brand-in-subdomain and
# non-standard ports were missing.
FEATURE_NAMES = ["url_length", "host_length", "n_dots", "n_hyphens", "n_digits",
                 "n_slashes", "has_at", "is_ip_host", "uses_https",
                 "n_bait_words", "risky_tld", "digit_ratio",
                 "domain_entropy", "brand_in_subdomain", "nonstandard_port"]


KNOWN_BRANDS = ["campusmail", "unilibrary", "cityhospital", "statebank",
                "bookdepot", "medplus", "codehub", "travelgo", "photolab"]


def shannon_entropy(text):
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 4)


MULTI_TLDS = ("ac.in", "co.in", "edu.in", "gov.in", "org.in", "net.in")


def registered_domain(host):
    """The part a user would recognise: brand + TLD, allowing for .ac.in etc."""
    host = host.split(":")[0].lower().rstrip(".")
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_TLDS:
        return ".".join(labels[-3:]), labels[:-3]
    if len(labels) >= 2:
        return ".".join(labels[-2:]), labels[:-2]
    return host, []


def brand_misplaced(host, path):
    """1 when a known brand name appears somewhere other than the registered
    domain - in a subdomain or in the path - which is the classic look-alike
    trick Gemini flagged as missing."""
    reg, subs = registered_domain(host)
    brand_in_reg = any(b in reg for b in KNOWN_BRANDS)
    brand_in_subs = any(b in s for s in subs for b in KNOWN_BRANDS)
    brand_in_path = any(b in path.lower() for b in KNOWN_BRANDS)
    if brand_in_reg:
        return 0
    return 1 if (brand_in_subs or brand_in_path) else 0


def extract(url: str):
    parsed = urlparse(url if "//" in url else "http://" + url)
    host = parsed.netloc
    low = url.lower()
    digits = sum(ch.isdigit() for ch in url)
    return [
        len(url),
        len(host),
        url.count("."),
        url.count("-"),
        digits,
        url.count("/"),
        1 if "@" in url else 0,
        1 if IP_RE.match(host.split(":")[0]) else 0,
        1 if parsed.scheme == "https" else 0,
        sum(w in low for w in BAIT_WORDS),
        1 if host.lower().endswith(RISKY_TLDS) else 0,
        round(digits / max(len(url), 1), 4),
        # --- added after the Gemini review ---
        shannon_entropy(host.split(":")[0].split(".")[0]),
        brand_misplaced(host, parsed.path),
        1 if ":" in host and not host.split(":")[-1] in ("80", "443", "") else 0,
    ]


def extract_many(urls):
    return [extract(u) for u in urls]
