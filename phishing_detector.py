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

SUSPICIOUS_TLDS = {
    "cam",
    "click",
    "country",
    "cyou",
    "icu",
    "mov",
    "quest",
    "rest",
    "stream",
    "support",
    "top",
    "work",
    "xyz",
    "zip",
}

MULTI_PART_PUBLIC_SUFFIXES = {
    "ac.uk",
    "co.in",
    "co.jp",
    "co.nz",
    "co.uk",
    "co.za",
    "com.ar",
    "com.au",
    "com.br",
    "com.mx",
    "com.sg",
    "com.tr",
    "gov.uk",
    "net.au",
    "org.au",
    "org.uk",
}

BRAND_DOMAINS = {
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de", "amazonaws.com"},
    "apple": {"apple.com"},
    "bankofamerica": {"bankofamerica.com"},
    "chase": {"chase.com"},
    "coinbase": {"coinbase.com"},
    "facebook": {"facebook.com", "fb.com"},
    "google": {"google.com", "google.co.uk", "googleapis.com", "gstatic.com"},
    "instagram": {"instagram.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "office365.com", "outlook.com"},
    "netflix": {"netflix.com"},
    "paypal": {"paypal.com", "paypal.co.uk"},
}

CREDENTIAL_URL_TERMS = {
    "account",
    "billing",
    "credential",
    "login",
    "password",
    "secure",
    "signin",
    "sign-in",
    "update",
    "verify",
    "wallet",
}

URL_PATTERN = re.compile(
    r"(?i)\b((?:https?://|www\.)[^\s<>'\"]+|[a-z0-9.-]+\.[a-z]{2,}(?:/[^\s<>'\"]*)?)"
)
FILE_PATTERN = re.compile(r"(?i)\b[\w .-]+\.(exe|scr|js|vbs|bat|cmd|msi|ps1|jar|iso|img|zip|rar|7z)\b")
IP_HOST_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
LOOKALIKE_TRANSLATION = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"})


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
            "findings": [
                {
                    "category": "Input",
                    "severity": "info",
                    "message": "Paste an email or URL to analyze it.",
                    "evidence": [],
                }
            ],
        }

    score = 0
    findings = []
    finding_index = {}
    lowered = text.lower()
    urls = extract_urls(text)
    url_only_scan = len(urls) == 1 and not re.search(r"\s", text.strip())

    def add_finding(points, category, severity, message, evidence=None, key=None):
        nonlocal score
        evidence = compact_evidence(evidence or [])
        key = key or (category, severity, message)

        if key in finding_index:
            existing = finding_index[key]
            existing["evidence"] = compact_evidence(existing["evidence"] + evidence)
            return

        score += points
        finding = {
            "category": category,
            "severity": severity,
            "message": message,
            "evidence": evidence,
        }
        findings.append(finding)
        finding_index[key] = finding

    urgency_matches = [word for word in URGENCY_WORDS if word in lowered]
    if urgency_matches:
        add_finding(
            min(25, 8 * len(urgency_matches)),
            "Language",
            "medium",
            "Uses urgency or pressure language.",
            sorted(urgency_matches)[:4],
            key=("language", "urgency"),
        )

    password_matches = [] if url_only_scan else [word for word in PASSWORD_REQUESTS if word in lowered]
    if password_matches:
        add_finding(
            min(30, 10 * len(password_matches)),
            "Credential request",
            "high",
            "Requests sensitive information such as passwords, codes, or account details.",
            sorted(password_matches)[:4],
            key=("language", "credentials"),
        )

    suspicious_files = [match.group(0).strip() for match in FILE_PATTERN.finditer(text)]
    if suspicious_files:
        extensions = sorted({f".{match.lower().rsplit('.', 1)[-1]}" for match in suspicious_files})
        add_finding(
            min(25, 10 * len(extensions)),
            "Attachment",
            "high",
            "Mentions risky attachment types.",
            extensions,
            key=("attachment", "risky-extension"),
        )

    if urls:
        analyze_urls(urls, add_finding)

    mismatches = find_mismatched_links(text)
    if mismatches:
        evidence = [f"{visible} -> {actual}" for visible, actual in mismatches]
        add_finding(
            min(35, 18 * len(mismatches)),
            "Link mismatch",
            "high",
            "Contains link text that appears to point to a different domain than the actual URL.",
            evidence,
            key=("html", "mismatched-link"),
        )

    if "reply with" in lowered and password_matches:
        add_finding(
            10,
            "Credential request",
            "high",
            "Asks the recipient to reply with sensitive information.",
            ["reply with"],
            key=("language", "reply-with-sensitive-info"),
        )

    score = min(100, score)
    if not findings:
        findings.append(
            {
                "category": "Clean scan",
                "severity": "info",
                "message": "No common phishing indicators were found by the current rule set.",
                "evidence": [],
            }
        )

    return {
        "score": score,
        "level": risk_level(score),
        "reasons": [finding["message"] + format_evidence(finding["evidence"]) for finding in findings[:6]],
        "findings": findings[:8],
    }


def extract_urls(text):
    urls = []
    for match in URL_PATTERN.findall(text):
        clean_url = match.rstrip(").,;!?]}")
        if clean_url.startswith("www."):
            clean_url = "https://" + clean_url
        elif not clean_url.startswith(("http://", "https://")):
            clean_url = "https://" + clean_url
        urls.append(clean_url)
    return dedupe(urls)


def analyze_urls(urls, add_finding):
    domains = []

    for url in urls:
        parsed = urlparse(url)
        host = normalize_host(parsed.netloc)
        if not host:
            continue

        domains.append(host)
        registered = registered_domain(host)
        label = registrable_label(host)
        tld = top_level_domain(host)

        if parsed.scheme == "http":
            add_finding(
                8,
                "Transport",
                "medium",
                "Uses an insecure http link.",
                [host],
                key=("url", "http", host),
            )

        if host in SHORTENERS:
            add_finding(
                20,
                "Link destination",
                "high",
                "Uses a shortened URL service.",
                [host],
                key=("url", "shortener", host),
            )

        if is_ip_host(host):
            add_finding(
                20,
                "Link destination",
                "high",
                "Uses an IP address instead of a recognizable domain.",
                [host],
                key=("url", "ip-host", host),
            )

        if "@" in url:
            add_finding(
                18,
                "URL obfuscation",
                "high",
                "Contains an @ symbol in a URL, which can hide the real destination.",
                [url],
                key=("url", "at-symbol", url),
            )

        if host.count(".") >= 3:
            add_finding(
                8,
                "Domain structure",
                "medium",
                "Uses a deep or unusual subdomain.",
                [host],
                key=("url", "deep-subdomain", host),
            )

        if is_punycode_host(host):
            add_finding(
                18,
                "Domain obfuscation",
                "high",
                "Uses punycode in the domain, which can disguise lookalike characters.",
                [host],
                key=("url", "punycode", host),
            )

        if tld in SUSPICIOUS_TLDS:
            add_finding(
                12,
                "Domain reputation",
                "medium",
                "Uses a domain ending commonly abused in phishing campaigns.",
                [registered],
                key=("url", "suspicious-tld", registered),
            )

        if label.count("-") >= 2:
            add_finding(
                8,
                "Domain structure",
                "medium",
                "Uses an unusually hyphenated domain label.",
                [registered],
                key=("url", "hyphenated-domain", registered),
            )

        brand = suspicious_brand_reference(registered)
        if brand:
            add_finding(
                26,
                "Brand impersonation",
                "high",
                "References a trusted brand from an unrelated domain.",
                [registered, brand],
                key=("url", "brand-reference", registered, brand),
            )

        lookalike = lookalike_brand_reference(label)
        if lookalike and registered not in BRAND_DOMAINS.get(lookalike, set()):
            add_finding(
                28,
                "Brand impersonation",
                "high",
                "Uses number substitutions that resemble a trusted brand.",
                [registered, lookalike],
                key=("url", "brand-lookalike", registered, lookalike),
            )

        credential_terms = credential_terms_in_url(url)
        if credential_terms:
            add_finding(
                16,
                "Credential path",
                "medium",
                "Uses account, login, or verification wording in the link.",
                [host] + credential_terms[:3],
                key=("url", "credential-path", host),
            )

    if len(set(domains)) >= 4:
        add_finding(
            8,
            "Link volume",
            "medium",
            "Contains several different link domains, which can be a sign of link stuffing.",
            sorted(set(domains))[:4],
            key=("url", "many-domains"),
        )


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
            mismatches.append((registered_domain(text_domain), registered_domain(href_domain)))

    return dedupe(mismatches)


def normalize_host(host):
    host = host.lower().strip().rstrip(".")
    if "@" in host:
        host = host.rsplit("@", 1)[-1]
    if ":" in host and not host.startswith("["):
        host = host.split(":", 1)[0]
    if host.startswith("www."):
        host = host[4:]
    return host


def registered_domain(host):
    parts = host.split(".")
    if len(parts) <= 2:
        return host

    suffix = ".".join(parts[-2:])
    if suffix in MULTI_PART_PUBLIC_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def registrable_label(host):
    registered = registered_domain(host)
    return registered.split(".", 1)[0]


def top_level_domain(host):
    return host.rsplit(".", 1)[-1] if "." in host else ""


def is_ip_host(host):
    if not IP_HOST_PATTERN.match(host):
        return False
    return all(0 <= int(part) <= 255 for part in host.split("."))


def is_punycode_host(host):
    return host.startswith("xn--") or ".xn--" in host


def suspicious_brand_reference(registered):
    label = registrable_label(registered).replace("-", "")
    for brand, allowed_domains in BRAND_DOMAINS.items():
        if brand in label and registered not in allowed_domains and label != brand:
            return brand
    return None


def lookalike_brand_reference(label):
    normalized = label.translate(LOOKALIKE_TRANSLATION).replace("-", "")
    compact_label = label.replace("-", "")
    if normalized == compact_label:
        return None

    for brand in BRAND_DOMAINS:
        if brand in normalized and brand not in compact_label:
            return brand
    return None


def credential_terms_in_url(url):
    lowered = url.lower()
    return sorted(term for term in CREDENTIAL_URL_TERMS if term in lowered)


def compact_evidence(items):
    return [str(item) for item in dedupe(items)[:4] if str(item)]


def dedupe(items):
    seen = set()
    unique = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique


def format_evidence(evidence):
    if not evidence:
        return ""
    return " Evidence: " + ", ".join(evidence) + "."


def risk_level(score):
    if score >= 70:
        return "High risk"
    if score >= 35:
        return "Medium risk"
    if score > 0:
        return "Low risk"
    return "No obvious risk"
