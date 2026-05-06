import re
from html.parser import HTMLParser
from urllib.parse import urlparse


URGENCY_WORDS = {
    "urgent",
    "immediately",
    "act now",
    "final notice",
    "limited time",
    "expires",
    "suspended",
    "locked",
    "verify now",
    "within 24 hours",
    "last warning",
}

PASSWORD_REQUESTS = {
    "password",
    "passcode",
    "login",
    "log in",
    "sign in",
    "credentials",
    "security code",
    "two-factor",
    "2fa",
    "otp",
    "social security",
    "ssn",
    "bank account",
    "credit card",
}

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "lnkd.in",
    "s.id",
}

SUSPICIOUS_ATTACHMENT_EXTENSIONS = {
    ".exe",
    ".scr",
    ".js",
    ".vbs",
    ".bat",
    ".cmd",
    ".msi",
    ".ps1",
    ".jar",
    ".iso",
    ".img",
    ".zip",
    ".rar",
    ".7z",
}

URL_PATTERN = re.compile(
    r"(?i)\b((?:https?://|www\.)[^\s<>'\"]+|[a-z0-9.-]+\.[a-z]{2,}(?:/[^\s<>'\"]*)?)"
)
FILE_PATTERN = re.compile(r"(?i)\b[\w .-]+\.(exe|scr|js|vbs|bat|cmd|msi|ps1|jar|iso|img|zip|rar|7z)\b")
IP_HOST_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self._active_link = None

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return

        attr_map = dict(attrs)
        href = attr_map.get("href")
        if href:
            self._active_link = {"href": href, "text": ""}
            self.links.append(self._active_link)

    def handle_endtag(self, tag):
        if tag.lower() == "a":
            self._active_link = None

    def handle_data(self, data):
        if self._active_link and data.strip():
            self._active_link["text"] += data.strip()


def analyze_text(text):
    if not text:
        return {
            "score": 0,
            "level": "No content",
            "reasons": ["Paste an email or URL to analyze it."],
        }

    score = 0
    reasons = []
    lowered = text.lower()
    urls = extract_urls(text)

    urgency_matches = [word for word in URGENCY_WORDS if word in lowered]
    if urgency_matches:
        score += min(25, 8 * len(urgency_matches))
        reasons.append("Uses urgency or pressure language: " + ", ".join(sorted(urgency_matches)[:4]) + ".")

    password_matches = [word for word in PASSWORD_REQUESTS if word in lowered]
    if password_matches:
        score += min(30, 10 * len(password_matches))
        reasons.append("Requests sensitive information such as passwords, codes, or account details.")

    suspicious_files = FILE_PATTERN.findall(text)
    if suspicious_files:
        score += min(25, 10 * len(suspicious_files))
        reasons.append("Mentions risky attachment types such as ." + ", .".join(sorted(set(suspicious_files))) + ".")

    if urls:
        score += analyze_urls(urls, reasons)

    mismatches = find_mismatched_links(text)
    if mismatches:
        score += min(35, 18 * len(mismatches))
        reasons.append("Contains link text that appears to point to a different domain than the actual URL.")

    if "reply with" in lowered and password_matches:
        score += 10
        reasons.append("Asks the recipient to reply with sensitive information.")

    score = min(100, score)
    if not reasons:
        reasons.append("No common phishing indicators were found by the current rule set.")

    return {
        "score": score,
        "level": risk_level(score),
        "reasons": reasons[:6],
    }


def extract_urls(text):
    urls = []
    for match in URL_PATTERN.findall(text):
        clean_url = match.rstrip(").,;!?]")
        if clean_url.startswith("www."):
            clean_url = "https://" + clean_url
        elif not clean_url.startswith(("http://", "https://")):
            clean_url = "https://" + clean_url
        urls.append(clean_url)
    return urls


def analyze_urls(urls, reasons):
    score = 0
    domains = []

    for url in urls:
        parsed = urlparse(url)
        host = normalize_host(parsed.netloc)
        domains.append(host)

        if parsed.scheme == "http":
            score += 8
            reasons.append(f"Uses an insecure http link: {host}.")

        if host in SHORTENERS:
            score += 20
            reasons.append(f"Uses a shortened URL service: {host}.")

        if IP_HOST_PATTERN.match(host):
            score += 20
            reasons.append("Uses an IP address instead of a recognizable domain.")

        if "@" in url:
            score += 18
            reasons.append("Contains an @ symbol in a URL, which can hide the real destination.")

        if host.count(".") >= 3:
            score += 8
            reasons.append(f"Uses a deep or unusual subdomain: {host}.")

        if has_suspicious_url_words(url):
            score += 10
            reasons.append(f"Uses suspicious wording in a link path or domain: {host}.")

    if len(set(domains)) >= 4:
        score += 8
        reasons.append("Contains several different link domains, which can be a sign of link stuffing.")

    return min(50, score)


def find_mismatched_links(text):
    parser = LinkParser()
    parser.feed(text)

    mismatches = []
    for link in parser.links:
        href_urls = extract_urls(link["href"])
        text_urls = extract_urls(link["text"])
        if not href_urls or not text_urls:
            continue

        href_domain = normalize_host(urlparse(href_urls[0]).netloc)
        text_domain = normalize_host(urlparse(text_urls[0]).netloc)
        if href_domain and text_domain and registered_domain(href_domain) != registered_domain(text_domain):
            mismatches.append((text_domain, href_domain))

    return mismatches


def normalize_host(host):
    host = host.lower().strip()
    if host.startswith("www."):
        host = host[4:]
    return host


def registered_domain(host):
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def has_suspicious_url_words(url):
    suspicious_terms = ("verify", "secure", "account", "login", "update", "password", "billing", "wallet")
    lowered = url.lower()
    return any(term in lowered for term in suspicious_terms)


def risk_level(score):
    if score >= 75:
        return "High risk"
    if score >= 40:
        return "Medium risk"
    if score > 0:
        return "Low risk"
    return "No obvious risk"
