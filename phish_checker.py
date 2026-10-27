"""
Phishing Link Checker
---------------------
A simple command-line tool that looks at a URL and flags common signs
of phishing. It only reads the text of the link. It never visits it,
so it is safe to run on suspicious links.

Usage:
    python phish_checker.py                  (asks you for a link)
    python phish_checker.py <url>            (checks one link)
    python phish_checker.py -f links.txt     (checks every link in a file)
"""

import re
import sys
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Data the checks use
# ---------------------------------------------------------------------------

# Free link shorteners hide where a link really goes.
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc",
}

# Cheap or free domain endings that scammers use a lot.
RISKY_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "zip", "mov",
    "click", "link", "work", "rest", "country", "buzz",
}

# Words phishing links use to sound urgent or official.
BAIT_WORDS = [
    "login", "signin", "verify", "verification", "secure", "account",
    "update", "confirm", "password", "banking", "suspend", "unlock",
    "wallet", "billing", "reward", "free",
]

# Brands people often impersonate, mapped to their real domains.
# If a link mentions the brand but is NOT on one of these domains,
# it is pretending to be something it is not.
BRANDS = {
    "paypal": ["paypal.com"],
    "google": ["google.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com"],
    "facebook": ["facebook.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "binance": ["binance.com"],
    "hbl": ["hbl.com"],
    "meezan": ["meezanbank.com"],
    "easypaisa": ["easypaisa.com.pk"],
    "jazzcash": ["jazzcash.com.pk"],
}

# Second-level endings like ".com.pk" or ".co.uk", so we can find the
# real registered domain (e.g. "easypaisa.com.pk", not "com.pk").
SECOND_LEVEL = {"com", "net", "org", "gov", "edu", "co", "ac"}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def get_hostname(url):
    """Return the hostname part of a URL in lowercase, e.g. 'www.google.com'."""
    # urlparse needs a scheme (http://) to find the hostname properly.
    if "://" not in url:
        url = "http://" + url
    return (urlparse(url).hostname or "").lower()


def get_registered_domain(hostname):
    """
    Return the domain someone actually registered.
    'login.paypal.com'         -> 'paypal.com'
    'hbl.verify-account.xyz'   -> 'verify-account.xyz'
    'www.easypaisa.com.pk'     -> 'easypaisa.com.pk'
    """
    # An IP address has no registered domain, so return it as it is.
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname):
        return hostname
    parts = hostname.split(".")
    if len(parts) >= 3 and parts[-2] in SECOND_LEVEL and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# ---------------------------------------------------------------------------
# The checks. Each one returns (points, reason) if it finds a problem,
# or None if the link passes. More points = more suspicious.
# ---------------------------------------------------------------------------

def check_ip_address(url, host):
    # Real websites use names. A raw number like 192.168.4.20 hides who owns it.
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        return 3, "Uses a raw IP address instead of a domain name"
    return None


def check_at_symbol(url, host):
    # Browsers ignore everything before '@', so
    # 'http://paypal.com@evil.com' actually goes to evil.com.
    if "@" in url:
        return 3, "Contains '@', which can hide the real destination"
    return None


def check_https(url, host):
    # No encryption. Note: HTTPS alone does NOT mean a site is safe.
    if url.lower().startswith("http://"):
        return 1, "Not using HTTPS (connection is not encrypted)"
    return None


def check_shortener(url, host):
    if host in SHORTENERS:
        return 2, "Uses a link shortener that hides the real destination"
    return None


def check_risky_tld(url, host):
    tld = host.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        return 2, f"Uses a domain ending (.{tld}) common in scams"
    return None


def check_punycode(url, host):
    # 'xn--' means the domain uses non-English letters that can look
    # identical to normal ones (e.g. a Cyrillic 'а' instead of 'a').
    if "xn--" in host:
        return 5, "Uses look-alike characters (punycode) to imitate another site"
    return None


def check_subdomains(url, host):
    # 'secure.login.paypal.account.evil.com' piles up words to look real.
    if host.count(".") >= 4:
        return 2, "Has an unusually high number of subdomains"
    return None


def check_length(url, host):
    if len(url) > 75:
        return 1, f"Very long URL ({len(url)} characters)"
    return None


def check_hyphens(url, host):
    # 'hbl-secure-login' style domains are a common trick.
    # Ignore the 'xn--' prefix, which the punycode check already covers.
    if host.replace("xn--", "").count("-") >= 2:
        return 1, "Domain contains many hyphens"
    return None


def check_bait_words(url, host):
    found = [w for w in BAIT_WORDS if w in url.lower()]
    if found:
        return 1, "Contains bait words: " + ", ".join(found)
    return None


def check_brand_impersonation(url, host):
    # The strongest sign: the link names a brand but is not on its real domain.
    real_domain = get_registered_domain(host)
    for brand, official in BRANDS.items():
        if brand in url.lower() and real_domain not in official:
            return 4, f"Mentions '{brand}' but the real domain is {real_domain}"
    return None


ALL_CHECKS = [
    check_ip_address,
    check_at_symbol,
    check_https,
    check_shortener,
    check_risky_tld,
    check_punycode,
    check_subdomains,
    check_length,
    check_hyphens,
    check_bait_words,
    check_brand_impersonation,
]


# ---------------------------------------------------------------------------
# Running the checks and giving a verdict
# ---------------------------------------------------------------------------

def analyse(url):
    """Run every check on a URL. Return (total score, list of reasons)."""
    url = url.strip()
    host = get_hostname(url)
    score = 0
    reasons = []
    for check in ALL_CHECKS:
        result = check(url, host)
        if result:
            points, reason = result
            score += points
            reasons.append(reason)
    return score, reasons


def verdict(score):
    if score >= 5:
        return "LIKELY PHISHING"
    if score >= 2:
        return "SUSPICIOUS"
    return "PROBABLY SAFE"


def report(url):
    score, reasons = analyse(url)
    print(f"\nURL:     {url}")
    print(f"Score:   {score}")
    print(f"Verdict: {verdict(score)}")
    for r in reasons:
        print(f"  - {r}")
    if not reasons:
        print("  - No warning signs found (this does not guarantee it is safe)")


def main():
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "-f":
        with open(args[1], encoding="utf-8") as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    report(line.strip())
    elif len(args) == 1:
        report(args[0])
    else:
        url = input("Paste a link to check: ")
        report(url)


if __name__ == "__main__":
    main()
