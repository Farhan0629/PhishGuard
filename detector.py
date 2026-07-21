"""Phishing detection engine.

Uses only stdlib: re, sys, math, argparse, ipaddress, dataclasses, urllib.parse.
Returns a SafetyReport with score (0-100), indicator, and a one-line reason.
"""

import argparse
import ipaddress
import math
import re
import sys
from dataclasses import dataclass, field
from typing import List
from urllib.parse import urlparse, unquote

from brands import (
    BRANDS, BRAND_ALIAS, LEGITIMATE_DOMAINS, DOMAIN_TO_BRAND,
)
from suspicious_lists import (
    SUSPICIOUS_TLDS, URL_SHORTENERS, ABUSIVE_FREE_DNS, SUSPICIOUS_FILE_HOSTS,
    SUSPICIOUS_KEYWORDS, SUSPICIOUS_QUERY_PARAMS, SUSPICIOUS_PATH_PATTERNS,
    HIGH_RISK_COUNTRY_TLDS, LOW_RISK_COUNTRY_TLDS,
)


# ----------------------------- Data model -------------------------------

@dataclass
class SafetyReport:
    score: int                       # 0 (definitely phishing) -> 100 (safe)
    indicator: str                   # "safe" | "likely_safe" | "suspicious" | "fake"
    reason: str                      # one-line explanation
    flags: List[str] = field(default_factory=list)


# ----------------------------- Constants --------------------------------

# Characters phishers commonly swap to mimic real brands.
HOMOGLYPHS = {
    "0": "o", "1": "l", "i": "l", "l": "1",
    "rn": "m", "vv": "w", "n": "m",
}

# Penalties for non-keyword signals. (Keyword penalties live in SUSPICIOUS_KEYWORDS.)
STRUCTURAL_PENALTIES = {
    "punycode":            35,
    "ip_host":             40,
    "partial_ip_host":     45,
    "url_shortener":       20,
    "abusive_free_dns":    25,
    "file_host":           15,
    "many_subdomains":     15,
    "long_host":           10,
    "long_path":           10,
    "encoded_chars":       20,
    "suspicious_tld":      25,
    "high_risk_country":   15,
    "suspicious_query":    12,
    "suspicious_path":     18,
    "suspicious_extension":25,
}


# ----------------------------- Helpers ----------------------------------

def _normalize(text: str) -> str:
    """Lowercase + strip protocol-ish noise + collapse."""
    t = text.lower()
    t = t.replace("rn", "m").replace("vv", "w")
    t = re.sub(r"[^a-z0-9.\-]", "", t)
    return t


def _levenshtein(a: str, b: str) -> int:
    """Pure-Python Levenshtein distance (small strings, no need for C ext)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr[j] = min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def _similar(a: str, b: str) -> float:
    """0..1 similarity score using Levenshtein."""
    if not a and not b:
        return 1.0
    dist = _levenshtein(a, b)
    longest = max(len(a), len(b))
    if longest == 0:
        return 1.0
    return 1.0 - dist / longest


def _registrable(host: str) -> str:
    """Best-effort 'registrable' domain (last two labels).
    For our heuristic purposes (small brand set), two-label root is enough.
    A real implementation would use the public-suffix list.
    """
    if not host:
        return ""
    parts = host.lower().split(".")
    if len(parts) <= 2:
        return host.lower()
    return ".".join(parts[-2:])


def _has_ip_address(host: str) -> bool:
    if not host:
        return False
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def _looks_like_ip(host: str) -> bool:
    if not host:
        return False
    if _has_ip_address(host):
        return True
    h = host.strip("[]")
    parts = h.split(".")
    if 1 <= len(parts) <= 4 and all(p.isdigit() for p in parts if p):
        return True
    return False


# ----------------------------- Scoring ----------------------------------

def analyze(url: str) -> SafetyReport:
    raw = (url or "").strip()
    flags: List[str] = []

    if not raw:
        return SafetyReport(0, "fake", "Empty input.", ["empty"])

    # Add a scheme if missing so urlparse has something to chew on.
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    full = (parsed.geturl() or "").lower()

    if not host:
        return SafetyReport(0, "fake", "Could not extract a domain from the URL.", ["no_host"])

    # ---------- Heuristics (each contributes a penalty) ----------

    # 1. Punycode / IDN homograph
    if "xn--" in host:
        flags.append("punycode")

    # 2. IP host (full or partial)
    if _has_ip_address(host):
        flags.append("ip_host")
    elif _looks_like_ip(host):
        flags.append("partial_ip_host")

    # 3. Excessive subdomains
    labels = [l for l in host.split(".") if l]
    if len(labels) > 4:
        flags.append("many_subdomains")

    # 4. Long host
    if len(host) > 50:
        flags.append("long_host")

    # 5. Long path
    if len(path) > 80:
        flags.append("long_path")

    # 6. Suspicious characters (encoded / userinfo bypass tricks)
    if re.search(r"[@%]|(%[0-9a-f]{2})", host):
        flags.append("encoded_chars")

    # 7. Suspicious TLDs
    is_low_risk = any(host.endswith(t) for t in LOW_RISK_COUNTRY_TLDS)
    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        if is_low_risk:
            # Not flagging here — the brand match will do the job.
            pass
        else:
            flags.append("suspicious_tld")

    # 7b. High-risk country-code TLD
    if any(host.endswith(t) for t in HIGH_RISK_COUNTRY_TLDS):
        flags.append("high_risk_country")

    # Compute registrable once
    registrable = _registrable(host)

    # 8. URL shortener
    if registrable in URL_SHORTENERS:
        flags.append("url_shortener")

    # 9. Abusive free-DNS / hosting
    if registrable in ABUSIVE_FREE_DNS:
        flags.append("abusive_free_dns")

    # 10. File host (often used to deliver payloads from "login" pages)
    if registrable in SUSPICIOUS_FILE_HOSTS:
        flags.append("file_host")

    # 11. Suspicious query parameters (very high signal: redirect=, password=, etc.)
    for q in parsed.query.split("&"):
        q = q.strip()
        if not q or "=" not in q:
            continue
        k = q.split("=", 1)[0].lower()
        # Strip array notation: foo[] -> foo
        k = re.sub(r"\[\]$", "", k)
        if k in SUSPICIOUS_QUERY_PARAMS:
            flags.append("suspicious_query")
            break

    # 12. Suspicious file extension in path
    if re.search(r"\.(exe|msi|apk|dmg|scr|jar|bat|cmd|vbs|ps1|iso|img|hta|cpl|wsf|js|docm|xlsm|pptm)\b", path, re.IGNORECASE):
        flags.append("suspicious_extension")

    # 13. Suspicious path patterns (regex set)
    for pat in SUSPICIOUS_PATH_PATTERNS:
        if re.search(pat, path + "?" + parsed.query, re.IGNORECASE):
            flags.append("suspicious_path")
            break

    # 14. Suspicious keywords (path, query, host)
    matched_words: list[str] = []
    full_norm = re.sub(r"[^a-z0-9.\-]", " ", full)
    for kw, _penalty in SUSPICIOUS_KEYWORDS.items():
        kw_norm = re.sub(r"\s+", "", kw.lower())
        # word-boundary-ish match on the normalized URL
        if re.search(rf"(^|[^a-z0-9]){re.escape(kw_norm)}([^a-z0-9]|$)", full_norm):
            matched_words.append(kw)
    # Don't double-penalize on near-duplicates: take up to 4 most-distinctive.
    seen_roots: set[str] = set()
    unique_matches: list[str] = []
    for kw in matched_words:
        root = kw.split("-")[0]
        if root in seen_roots:
            continue
        seen_roots.add(root)
        unique_matches.append(kw)
        if len(unique_matches) >= 4:
            break
    for kw in unique_matches:
        flags.append("keyword_" + kw.replace("-", "_"))

    # ---------- Brand impersonation ----------

    best_brand, best_sim, best_legit = "", 0.0, ""
    norm_registrable = _normalize(registrable)

    def _brand_token_present(norm_host: str, brand_name: str) -> bool:
        tokens = set()
        tokens.add(brand_name.lower().replace(" ", ""))
        for w in brand_name.lower().split():
            if len(w) >= 5:
                tokens.add(w)
        for t in tokens:
            if len(t) >= 4 and t in norm_host:
                return True
        return False

    def _homoglyph_close(norm_host: str, brand_name: str) -> bool:
        tokens = {"".join(p for p in brand_name.lower().split() if p)}
        host_tokens = re.split(r"[^a-z0-9]+", norm_host)
        for ht in host_tokens:
            if len(ht) < 4:
                continue
            for bt in tokens:
                if len(bt) < 4:
                    continue
                if bt in ht or ht in bt:
                    return True
                len_diff = abs(len(ht) - len(bt))
                if len_diff <= 1 and _levenshtein(ht, bt) <= 1:
                    return True
        return False

    compound_hit_brand: tuple[str, str] | None = None
    for brand_name, legit_domains in BRANDS:
        if _brand_token_present(norm_registrable, brand_name):
            compound_hit_brand = (brand_name, legit_domains[0])
            break
    if not compound_hit_brand:
        for brand_name, legit_domains in BRANDS:
            if _homoglyph_close(norm_registrable, brand_name):
                compound_hit_brand = (brand_name, legit_domains[0])
                break

    # Whole-domain Levenshtein
    for brand, legit_domains in BRANDS:
        for legit in legit_domains:
            sim = _similar(norm_registrable, _normalize(legit))
            if sim > best_sim:
                best_sim = sim
                best_brand = brand
                best_legit = legit

    # ---------- Decision branches ----------

    # 1. User is on an official domain.
    if registrable in LEGITIMATE_DOMAINS:
        structural_flags = [f for f in flags if not f.startswith("keyword_")]
        score = 100
        for f in structural_flags:
            score -= STRUCTURAL_PENALTIES.get(f, 0)
        score = max(0, min(100, score))
        display_brand = BRAND_ALIAS.get(registrable, DOMAIN_TO_BRAND[registrable])
        return SafetyReport(
            score=score,
            indicator="safe" if score >= 80 else "likely_safe",
            reason=f"Hosted on the official {display_brand} domain ({registrable}).",
            flags=flags,
        )

    # 2. Brand impersonation hit.
    brand_impersonation = (best_sim >= 0.78 and best_brand) or bool(compound_hit_brand)
    if brand_impersonation:
        if compound_hit_brand:
            hit_brand, hit_legit = compound_hit_brand
            verb = "contains"
        else:
            hit_brand, hit_legit = best_brand, best_legit
            verb = "resembles"
        flags.append("brand_impersonation")
        return SafetyReport(
            score=5,
            indicator="fake",
            reason=(
                f"Domain '{registrable}' {verb} the brand name {hit_brand} "
                f"({hit_legit}) but isn't an official {hit_brand} address."
            ),
            flags=flags,
        )

    # 3. Build a score from the remaining flags.
    base = 85
    for f in flags:
        if f.startswith("keyword_"):
            kw = f[len("keyword_"):].replace("_", "-")
            base -= SUSPICIOUS_KEYWORDS.get(kw, 5)
        elif f == "url_shortener":
            base -= 20
        else:
            base -= STRUCTURAL_PENALTIES.get(f, 0)

    score = max(0, min(100, base))

    # 4. Decide indicator + one-line reason.
    first_keyword = unique_matches[0] if unique_matches else None
    if score >= 85:
        indicator = "safe"
        reason = f"No major red flags found on {registrable}."
    elif score >= 65:
        indicator = "likely_safe"
        reason = f"{registrable} looks generally clean, with a few minor warning signs."
    elif score >= 40:
        indicator = "suspicious"
        if "suspicious_tld" in flags:
            reason = f"Uses a top-level domain ({registrable.split('.')[-1]}) that phishers often register."
        elif "ip_host" in flags:
            reason = f"Uses a raw IP address ({host}) instead of a normal domain name."
        elif "partial_ip_host" in flags:
            reason = f"Looks like a partial or malformed IP address ({host})."
        elif "punycode" in flags:
            reason = f"Uses a punycode/IDN host ({host}), a common homograph trick."
        elif "abusive_free_dns" in flags:
            reason = f"Hosted on a free dynamic-DNS service ({registrable}) frequently abused for phishing."
        elif "file_host" in flags:
            reason = f"Hosted on a file-sharing service ({registrable}) that is often abused to deliver payloads."
        elif "url_shortener" in flags:
            reason = f"Hides the real destination behind a URL shortener ({registrable})."
        elif "suspicious_path" in flags:
            reason = f"Path matches a common phishing pattern ('{path[:40]}')."
        elif "suspicious_extension" in flags:
            reason = f"Path points to a download ({path.rsplit('/', 1)[-1]}) that executables often pretend to be."
        elif "suspicious_query" in flags:
            reason = "Query string contains parameters typically used in credential-harvesting links."
        elif "high_risk_country" in flags:
            reason = f"Uses a country-code TLD ({host.split('.')[-1]}) commonly seen in phishing infrastructure."
        elif first_keyword:
            reason = f"Contains the suspicious keyword '{first_keyword}' and a less-common structure."
        else:
            reason = f"{registrable} has several warning signs worth a second look."
    else:
        indicator = "fake"
        if "ip_host" in flags:
            reason = f"Uses a raw IP address ({host}) instead of a real domain — typical phishing pattern."
        elif "partial_ip_host" in flags:
            reason = f"Looks like a partial or malformed IP address ({host}) — no real domain name."
        elif "url_shortener" in flags and first_keyword:
            reason = f"Hides the destination behind a shortener ({registrable}) and asks for '{first_keyword}'."
        elif "url_shortener" in flags:
            reason = f"Hides the real destination behind a URL shortener ({registrable})."
        elif "abusive_free_dns" in flags:
            reason = f"Hosted on a free dynamic-DNS service ({registrable}) commonly abused for phishing."
        elif "file_host" in flags:
            reason = f"Hosted on a file-sharing service ({registrable}) — phishers often stash payloads there."
        elif "suspicious_extension" in flags:
            reason = f"Path points to an executable ({path.rsplit('/', 1)[-1]}) — likely malware delivery."
        elif "suspicious_path" in flags:
            reason = f"Path matches a known phishing pattern ('{path[:40]}')."
        elif "suspicious_tld" in flags:
            reason = f"Top-level domain is one frequently abused for phishing and scams."
        elif "high_risk_country" in flags:
            reason = f"Country-code TLD ({host.split('.')[-1]}) is one frequently abused by phishing infrastructure."
        elif first_keyword:
            reason = f"Combines a suspicious keyword ('{first_keyword}') with risky URL patterns."
        else:
            reason = f"Multiple red flags on {registrable} suggest a likely phishing URL."

    return SafetyReport(score=score, indicator=indicator, reason=reason, flags=flags)


# ----------------------------- CLI --------------------------------------

def _indicator_color(indicator: str) -> str:
    return {
        "safe":        "\033[92m",
        "likely_safe": "\033[96m",
        "suspicious":  "\033[93m",
        "fake":        "\033[91m",
    }.get(indicator, "")
RESET = "\033[0m"


def _main_cli(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="Phishing URL detector (CLI).")
    parser.add_argument("url", help="URL to check")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI color")
    args = parser.parse_args(argv)

    report = analyze(args.url)
    if args.no_color:
        print(f"[{report.indicator.upper()}] score={report.score}/100 — {report.reason}")
    else:
        c = _indicator_color(report.indicator)
        print(f"{c}[{report.indicator.upper()}]{RESET} score={report.score}/100 — {report.reason}")
    return 0


if __name__ == "__main__":
    sys.exit(_main_cli(sys.argv[1:]))
