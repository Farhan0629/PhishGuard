# PhishGuard — Heuristic Phishing URL Detector

A self-contained, zero-dependency phishing URL analyzer. Type (or paste) a
URL, and PhishGuard returns a **0–100 safety score**, a verdict
(`Safe` / `Likely Safe` / `Suspicious` / `Likely Fake`), a one-line
explanation, and the heuristic flags that fired.

> **Heuristic only — not a substitute for a real security product.**
> PhishGuard is a learning/demonstration tool. It catches a *lot* of
> common phishing patterns but it does not fetch the URL, does not
> inspect the page, and does not replace a real-time blocklist.

The look is a deliberate SOC-terminal / CRT-phosphor aesthetic:
monospace fonts, scanline overlay, ASCII frame bezel, glitch title,
type-on result text, and a 24-cell ASCII safety meter. Everything
under the hood is plain Python + stdlib + a tiny static frontend.

---

## Table of contents

- [Highlights](#highlights)
- [Quick start](#quick-start)
- [Deploy live](#deploy-live)
- [Usage](#usage)
  - [Web UI](#web-ui)
  - [CLI](#cli)
  - [HTTP API](#http-api)
- [How detection works](#how-detection-works)
  - [Score model](#score-model)
  - [The 28 signals](#the-28-signals)
  - [Verdict thresholds](#verdict-thresholds)
- [Brand coverage](#brand-coverage)
  - [All 27 categories](#all-27-categories)
  - [Indian phishing surface](#indian-phishing-surface)
  - [Curated, not exhaustive](#curated-not-exhaustive)
- [Project layout](#project-layout)
- [The frontend](#the-frontend)
- [Limitations & threat model](#limitations--threat-model)
- [Extending PhishGuard](#extending-phishguard)
- [License](#license)

---

## Highlights

- **Zero dependencies** — pure Python stdlib. No `pip install` required.
- **480+ brand entries / 730+ legitimate domains** across 27 categories,
  with heavy coverage of Indian banks, UPI apps, government portals,
  telecom, and the AI-tool surface.
- **Heuristic engine** combining 28 signals: brand typosquatting
  (Levenshtein), homoglyph detection, suspicious TLDs, suspicious
  keywords, free-DNS abuse, IP-as-host, IDN/punycode, subdomain
  stuffing, and more.
- **Two frontends** — a SOC-styled web UI and a CLI tool.
- **JSON API** — every result the UI shows is also a single
  `POST /api/check` call away.
- **Single-file static frontend** — no build step, no framework, no
  bundler.

---

## Quick start

```bash
# 1. Clone or copy the project, then:
cd "Phishing detector"

# 2. Start the web server
python app.py
#   Phishing detector running on http://0.0.0.0:5000

# 3. Open http://127.0.0.1:5000 in a browser
```

That's it. No `requirements.txt`. No virtualenv. The Python version
required is **3.8+** (uses `dataclasses`, `f-strings`, and
`urllib.parse` features available everywhere since 3.8).

### Quick test from the command line

```bash
python detector.py "https://rnicrosoft.com/account/verify"
# [FAKE] score=5/100 — Domain 'rnicrosoft.com' looks like Microsoft (microsoft.com) but isn't an official Microsoft address.

python detector.py "https://paypal.com/signin"
# [SAFE] score=82/100 — Hosted on the official PayPal domain (paypal.com).

python detector.py "http://sbi-kyc-update.in/login"
# [SUSPICIOUS] score=43/100 — Domain 'sbi-kyc-update.in' contains the brand name SBI (sbi.co.in) but isn't an official SBI address.
```

---

## Deploy live

PhishGuard is deploy-ready on any Python host (Render, Railway, Fly.io,
VMs, etc.).

- Start command: `python app.py`
- Process file included: `Procfile` (`web: python app.py`)
- Runtime bind: `HOST` (default `0.0.0.0`) and `PORT` env var (default
  `5000`)

After deployment, open your platform-provided public URL.

---

## Usage

### Web UI

1. Run `python app.py`.
2. Open <http://127.0.0.1:5000>.
3. Paste a URL, press **RUN** (or hit Enter), or click any of the
   sample chips (`rnicrosoft.com`, `netf1ix.com`, `amaz0n-security-update.com`,
   `192.168.1`, `servehttp.com`, `paypal.com/signin`,
   `sbi-kyc-update.in`, `irctc-refund.tk`).
4. Read the result panel:
   - **LED + label** — verdict (`SAFE` / `LIKELY SAFE` / `SUSPICIOUS` / `LIKELY FAKE`).
   - **Tier tag** — `[ TIER-0 :: CLEAN ]` … `[ TIER-3 :: MALICIOUS ]`.
   - **Score** — 0–100 with a glitched reveal animation.
   - **24-cell ASCII meter** — visual progress of the score.
   - **Reason** — one-line plain-English explanation (type-on reveal).
   - **Flags** — the heuristic signals that fired (`brand_impersonation`,
     `suspicious_tld`, `homoglyph`, …).

The CRT scanlines, ASCII frame, and glitch title are decorative;
they do not affect scoring.

### CLI

```bash
python detector.py [--no-color] <url>
```

- `--no-color` — strip ANSI color codes (useful when piping to a file
  or `less -R`).
- `<url>` — quoted URL to analyze.

Exit status is always 0; the verdict is shown in the output and via
the color (green = safe, cyan = likely safe, amber = suspicious, red =
likely fake).

### HTTP API

**Endpoint:** `POST /api/check`
**Content-Type:** `application/json`
**Body:** `{"url": "https://example.com/login"}`

**Response 200:**

```json
{
  "url":       "https://rnicrosoft.com/account/verify",
  "score":     5,
  "indicator": "fake",
  "label":     "Likely Fake",
  "color":     "#dc2626",
  "reason":    "Domain 'rnicrosoft.com' looks like Microsoft (microsoft.com) but isn't an official Microsoft address.",
  "flags":     ["brand_impersonation", "suspicious_tld", "suspicious_keyword"]
}
```

**Response 400** — invalid JSON or missing `url`.
**Response 404** — wrong path.

**Health check:** `GET /api/health` → `{"ok": true}`.

**CORS:** `Access-Control-Allow-Origin: *` is set, so the API can be
called directly from a browser or another origin.

Example with `curl`:

```bash
curl -X POST http://127.0.0.1:5000/api/check \
  -H "Content-Type: application/json" \
  -d '{"url":"http://irctc-refund.tk/"}'
```

---

## How detection works

PhishGuard is **purely URL-string-based**. It never makes a network
request, never fetches HTML, never resolves DNS. Everything is decided
from the characters in the URL itself.

### Score model

Every URL starts at a baseline and gets penalties subtracted. The
final score is clamped to `[0, 100]`.

| Stage                           | Result     | Score   |
|---------------------------------|------------|---------|
| **Official domain hit**         | Trusted    | **82–100** (path/keyword flags may trim) |
| Brand-typosquat (≥ 0.78 similarity to a known brand) | **FAKE** | **5** (overrides everything) |
| All other URLs                  | Heuristic  | `85 − Σ(penalties)`, clamped to `[0, 85]` |

This split is intentional. A real phish that *perfectly* impersonates
a brand (e.g. `rnicrosoft.com` with the Microsoft logo in the path)
should not score 60 just because the TLD happens to be `.com` — the
brand-mismatch is the dominant signal, and it short-circuits to 5.

If the host *is* an official brand domain, the path can still trip
flags (`login`, `verify`, `secure-account`) but the score is anchored
high.

### The 28 signals

Signals are evaluated in order. Each contributes a flag (rendered in
the UI) and, where relevant, a numeric penalty.

#### Brand impersonation

1. **Levenshtein brand typosquat** — every URL host is compared to
   every legitimate domain in `brands.py`. If the similarity ratio
   (1 − edit_distance / max_length) is ≥ **0.78**, it's flagged
   `brand_impersonation`. Severity: **score = 5** (override).
2. **Substring brand mention** — if a legitimate brand's name (or one
   of its known domain tokens) appears inside the host *but* the host
   isn't on the legitimate list, it's flagged `brand_impersonation`
   (e.g. `sbi-kyc-update.in` contains "sbi").
3. **Homoglyph substitution** — common character swaps phishers use
   to mimic a real brand (`0`↔`o`, `1`↔`l`, `rn`↔`m`, `vv`↔`w`,
   `cl`↔`d`). Flagged `homoglyph`.
4. **Mixed-script host (IDN/punycode)** — `xn--` prefix or a mix of
   Cyrillic / Greek / fullwidth Latin in the host. Flagged
   `punycode_idn` with a **−35** penalty.

#### Host / network

5. **Raw IP as host** — the host parses as a valid IPv4 or IPv6
   literal. Flagged `ip_address` with **−40**.
6. **Looks-like-IP** — host matches the dotted-quad pattern but
   `ipaddress` rejects it (e.g. `192.168.1` is suspicious, `999.1.1.1`
   is too). Flagged `looks_like_ip` with **−25**.
7. **Free-DNS / abusive host** — host ends in a domain on the
   `ABUSIVE_FREE_DNS` list (e.g. `servehttp.com`, `duckdns.org`).
   Flagged `abusive_free_dns` with **−30**.
8. **Subdomain stuffing** — more than 4 labels in the host
   (`a.b.c.d.e.example.com`). Flagged `many_subdomains` with **−15**.
9. **Long host** — hostname longer than 50 characters. Flagged
   `long_host` with **−10**.

#### TLD

10. **Suspicious TLD** — host uses one of 40+ known-abused TLDs
    (`.zip`, `.top`, `.tk`, `.gq`, `.ml`, `.ga`, `.cf`, `.xyz`,
    `.click`, `.country`, `.work`, `.support`, etc.). Flagged
    `suspicious_tld` with **−25**.

#### Path / query

11. **Suspicious file host** — host is a known pastebin / file host
    (`pastebin.com`, `gist.github.com`, `raw.githubusercontent.com`,
    `transfer.sh`, …) **and** the URL is `http://`. Flagged
    `suspicious_file_host` with **−30**.
12. **Suspicious keywords in path** — any of 60+ tokens
    (`login`, `verify`, `secure`, `update`, `account`, `wallet`,
    `kyc`, `reset`, `signin`, `auth`, `confirm`, `recover`, …) appear
    in the path. Each match flagged `suspicious_keyword` with **−4 to
    −10** depending on the keyword.
13. **Suspicious query parameters** — presence of `redirect`,
    `redirect_uri`, `url`, `next`, `return`, `continue`, `goto`,
    `target`, `dest`, `rurl`. Flagged `suspicious_query_param` with
    **−6 each** (capped at 3).
14. **Suspicious path patterns** — regex patterns matching
    phishing-typical paths (`/wp-admin/`, `/cgi-bin/`, `.php?`,
    `verify-` etc.). Flagged `suspicious_path` with **−6**.
15. **Encoded characters in host** — `%`, `%xx` (URL-encoded chars),
    or `@` inside the host (the classic
    `https://google.com@evil.com/` trick). Flagged `encoded_chars`
    with **−20**.

#### URL shorteners

16. **Known URL shortener** — host is one of 30+ shorteners
    (`bit.ly`, `tinyurl.com`, `t.co`, `t.me`, `is.gd`, `cutt.ly`,
    `rebrand.ly`, …). Flagged `url_shortener`. **No score penalty**
    by itself (the shortener is allowed, just noted), but combined
    with other flags it pushes the URL into `Suspicious` territory.

#### Country-code TLDs

17. **High-risk ccTLD** — `.ru`, `.cn`, `.su`, `.tk`. Flagged
    `high_risk_country` with **−15**.
18. **Low-risk ccTLD** — `.gov`, `.edu`, `.mil`, `.int`, `.ac.uk`,
    `.gov.uk`, etc. Flagged `low_risk_country` (no penalty, used
    to *boost* trust slightly).

#### Meta signals

19. **Missing HTTPS** — scheme is `http://`. Flagged `no_https` with
    **−10**.
20. **Very long URL** — total URL length > 200 characters. Flagged
    `very_long_url` with **−10**.

> **Heuristic priority.** When the brand-typosquat check fires
> (similarity ≥ 0.78), PhishGuard **stops** and returns `score=5`
> with indicator `fake`. This is by design: a perfect homoglyph
> domain is the strongest single signal, and it should dominate the
> result even if the rest of the URL is otherwise clean.

### Verdict thresholds

| Score range  | Indicator      | Label        |
|-------------:|----------------|--------------|
| 70–100       | `safe`         | SAFE         |
| 50–69        | `likely_safe`  | LIKELY SAFE  |
| 30–49        | `suspicious`   | SUSPICIOUS   |
| 0–29         | `fake`         | LIKELY FAKE  |

Brand-typosquat override: always `fake / 5` regardless of where the
heuristic score would otherwise land.

---

## Brand coverage

`brands.py` ships with **480+ brand entries** mapping to **730+
legitimate domains** across **27 categories**. Every entry is a
`(canonical_name, [legit_domains])` tuple. The module also maintains
a `BRAND_ALIAS` table so a URL like `onlinesbi.sbi` displays as
`"SBI"` in the UI rather than the raw hostname.

### All 27 categories

| # | Category          | # brands | Examples |
|---:|-------------------|---------:|----------|
| 1  | TECH              | 38 | Microsoft, Apple, Google, Meta, Amazon, Netflix, Adobe, Atlassian, Cisco, Oracle, SAP, Salesforce, … |
| 2  | SOCIAL            | 22 | Twitter/X, LinkedIn, Instagram, TikTok, Reddit, Discord, Telegram, Signal, Threads, Bluesky, … |
| 3  | EMAIL             | 5  | Yahoo, GMX, AOL, Zoho, Fastmail |
| 4  | FINANCE           | 42 | Bank of America, Chase, HSBC, Barclays, ANZ, Westpac, Revolut, N26, Robinhood, Vanguard, … |
| 5  | CRYPTO            | 32 | Coinbase, Binance, Kraken, MetaMask, Phantom, Ledger, Trezor, Uniswap, OpenSea, … |
| 6  | RETAIL            | 37 | Walmart, Target, Costco, IKEA, Alibaba, Shein, Temu, Nike, Etsy, Shopify, … |
| 7  | DELIVERY          | 20 | DHL, FedEx, UPS, USPS, Royal Mail, SF Express, JD Logistics, Maersk, MSC, … |
| 8  | TRAVEL            | 33 | Delta, United, BA, Lufthansa, Emirates, Marriott, Hilton, Booking, Expedia, … |
| 9  | HEALTH            | 17 | UnitedHealth, Aetna, Cigna, CVS, Walgreens, Mayo Clinic, Teladoc, … |
| 10 | GAMING            | 23 | Steam, Epic, Roblox, EA, Ubisoft, PlayStation, Nintendo, Spotify, HBO Max, … |
| 11 | GOV               | 17 | IRS, HMRC, CRA, ATO, SSA, Medicare, FDA, FBI, FTC, NHS, … |
| 12 | DEV               | 43 | GitHub, GitLab, Cloudflare, Fastly, Vercel, Netlify, Supabase, OpenAI, Anthropic, Okta, 1Password, Bitwarden, Norton, McAfee, … |
| 13 | **INDIAN_BANKS**  | 23 | SBI, HDFC, ICICI, Axis, PNB, Bank of Baroda, Union, Canara, Indian Bank, IDFC FIRST, Kotak, Yes, IndusInd, AU SFB, Federal, UCO, Central, South Indian, Karnataka, Bandhan, RBL, CUB, BoI |
| 14 | **UPI**           | 13 | PhonePe, Google Pay IN, Paytm, BHIM, Amazon Pay, Mobikwik, Freecharge, Razorpay, Cashfree, CRED, BharatPe, Pine Labs, Juspay |
| 15 | **INDIAN_GOV**    | 20 | UIDAI, DigiLocker, UMANG, Income Tax, GST, EPFO, NPCI, Passport Seva, MCA, PM Kisan, PM Jan Dhan, CoWIN, NSP, JEE Main, NTA, UPSC, SSC, IRCTC, GeM, MyGov |
| 16 | **INDIAN_ECOMMERCE** | 13 | Flipkart, Myntra, Meesho, AJIO, Nykaa, Tata CliQ, Snapdeal, JioMart, FirstCry, Pepperfry, Reliance Digital, Croma, Vijay Sales |
| 17 | **INDIAN_TELECOM** | 5 | Jio, Airtel, Vi, BSNL, MTNL |
| 18 | **INDIAN_DELIVERY** | 9 | India Post, Delhivery, Blue Dart, DTDC, XpressBees, Shadowfax, Ecom Express, Ekart, Porter |
| 19 | **INDIAN_TRAVEL** | 9 | MakeMyTrip, Goibibo, Yatra, EaseMyTrip, RedBus, AbhiBus, ConfirmTkt, ixigo, Cleartrip |
| 20 | **INDIAN_FOOD**   | 6 | Zomato, Swiggy, Blinkit, Zepto, BigBasket, Instamart |
| 21 | **INDIAN_INSURANCE** | 10 | LIC, SBI Life, HDFC Life, ICICI Prudential, Tata AIA, Max Life, Bajaj Allianz, Star Health, Niva Bupa, Care Health |
| 22 | **INDIAN_INVESTMENT** | 10 | Groww, Zerodha, Angel One, Upstox, 5Paisa, Paytm Money, INDmoney, ET Money, Kuvera, Motilal Oswal |
| 23 | **INDIAN_EDUCATION** | 9 | Coursera, Udemy, Unacademy, BYJU'S, Vedantu, Physics Wallah, Khan Academy, NPTEL, SWAYAM |
| 24 | **INDIAN_OTT**    | 7 | JioHotstar, Sony LIV, Zee5, JioCinema, Prime Video, Netflix, Apple TV+, MX Player |
| 25 | **INDIAN_UTILITIES** | 7 | WBSEDCL, CESC, Tata Power, Adani Electricity, BESCOM, MSEB, UPPCL |
| 26 | **INDIAN_GAS**    | 3 | Indane, Bharat Gas, HP Gas |
| 27 | **INDIAN_CRYPTO** | 5 | CoinDCX, CoinSwitch, Mudrex, Giottus, WazirX |
| 28 | **CLOUD_AI**      | 8 | Perplexity, Claude, Grok, Cursor, Windsurf, Replit, Lovable, Bolt.new |

### Indian phishing surface

A large slice of real-world phishing today targets Indian consumers
and small businesses (UPI fraud, fake KYC portals, fake courier
delivery SMS, fake Aadhaar/EPFO updates, fake recharge links,
fake IPO/stock tips). The dataset is built around the services that
are *actually* impersonated in India:

- **Indian banks** — 23 of the largest public/private sector banks
  (SBI, HDFC, ICICI, Axis, PNB, BoB, Union, Canara, Indian Bank, IDFC
  FIRST, Kotak, Yes, IndusInd, AU SFB, Federal, UCO, Central, South
  Indian, Karnataka, Bandhan, RBL, CUB, BoI).
- **UPI & payment apps** — PhonePe, Google Pay, Paytm, BHIM, Amazon
  Pay, Mobikwik, Freecharge, Razorpay, Cashfree, CRED, BharatPe,
  Pine Labs, Juspay.
- **Indian government portals** — UIDAI, DigiLocker, UMANG, Income
  Tax, GST, EPFO, NPCI, Passport Seva, MCA, PM Kisan, PM Jan Dhan,
  CoWIN, NSP, JEE Main, NTA, UPSC, SSC, IRCTC, GeM, MyGov.
- **Telecom** — Jio, Airtel, Vi, BSNL, MTNL.
- **Delivery & logistics** — India Post, Delhivery, Blue Dart, DTDC,
  XpressBees, Shadowfax, Ecom Express, Ekart, Porter.
- **Investment / broking** — Groww, Zerodha, Angel One, Upstox,
  5Paisa, Paytm Money, INDmoney, ET Money, Kuvera, Motilal Oswal.
- **Food delivery, travel, OTT, insurance, utilities, gas, education,
  e-commerce, crypto** — all the rest of the Indian consumer-internet
  surface.

### Curated, not exhaustive

The dataset aims for **~700–1,000 legitimate domains** focused on
services that are *actually* impersonated in phishing campaigns —
not a million-entry blocklist. Each addition passes three checks:

1. The brand is **currently being spoofed** in real phishing reports
   (public feeds, vendor writeups, CERT-In advisories).
2. The legitimate domain list comes from the **brand's own site**
   (verified in 2025–2026).
3. The brand has enough reach that impersonation is worth catching
   (regional banks and very small SaaS apps are skipped).

If you want to add a new brand, edit `brands.py` and add a tuple to
the relevant section. The module runs its own dedup + duplicate-brand
checks on import and will fail loudly if you reuse a domain across
two brands.

---

## Project layout

```
Phishing detector/
├── app.py                # stdlib http.server: serves frontend + /api/check
├── detector.py           # heuristic engine, CLI entry point
├── brands.py             # 480+ brand entries, 27 categories
├── suspicious_lists.py   # TLDs, free-DNS, shorteners, keywords, ccTLDs
├── static/
│   ├── index.html        # single-page UI
│   ├── style.css         # CRT-terminal styles
│   └── script.js         # fetch + render + animations
├── README.md             # this file
└── __pycache__/          # python bytecode cache
```

### File responsibilities

- **`brands.py`** — the brand database. Pure data, no logic. The
  `BRANDS` aggregator at the bottom is the single source of truth
  consumed by `detector.py`.
- **`suspicious_lists.py`** — TLDs, free-DNS hosts, URL shorteners,
  suspicious keywords, suspicious query parameters, country-code
  TLDs, and high-risk country TLDs. Also pure data.
- **`detector.py`** — the only file with logic. Parses the URL,
  walks every signal, returns a `SafetyReport(score, indicator,
  reason, flags)`. Has no external dependencies. Exposes both the
  CLI (`python detector.py <url>`) and the `analyze(url)` function
  imported by `app.py`.
- **`app.py`** — stdlib `http.server` (Flask would be overkill and
  the project explicitly wants zero deps). Serves `/static/*` and
  exposes `POST /api/check`.
- **`static/index.html`**, **`style.css`**, **`script.js`** — the
  frontend. No build step, no framework, no bundler. Just three
  files served straight off disk.

---

## The frontend

The frontend is a single static page with a deliberate
**CRT-phosphor / SOC-terminal** aesthetic. It contains *no
information that isn't already in the JSON response* — all the
visual flourishes (scanlines, ASCII frame bezel, glitch title,
type-on result text, glitched score reveal, 24-cell ASCII safety
meter) are there to make the tool feel like a console, not to add
signal.

What you see on screen:

1. **Title block** — `root@soc-01:~$ ./phishguard --analyze`,
   glitched `PHISHGUARD` heading, one-line subtitle.
2. **Input console** — `target.url` field with a `>>` caret prefix
   and a `[RUN]` button. Sample chips below for quick testing
   (`rnicrosoft.com`, `netf1ix.com`, `amaz0n-security-update.com`,
   `192.168.1`, `servehttp.com`, `paypal.com/signin`,
   `sbi-kyc-update.in`, `irctc-refund.tk`).
3. **Result panel** — appears after the first scan:
   - **LED + label** — colored circle (green/cyan/amber/red) and the
     indicator text (`SAFE`, `LIKELY SAFE`, `SUSPICIOUS`, `LIKELY FAKE`).
   - **Tier tag** — `[ TIER-0 :: CLEAN ]` … `[ TIER-3 :: MALICIOUS ]`.
   - **Score** — 0–100 with a glitched glyph reveal.
   - **ASCII meter** — 24-cell progress bar shaped like
     `[████░░░░░░░░░░░░░░░░░░░░]`.
   - **Reason** — one-line plain-English explanation, type-on
     reveal with a blinking cursor.
   - **Flags** — every heuristic signal that fired
     (`brand_impersonation`, `suspicious_tld`, `homoglyph`, …).
4. **Footer disclaimer** — `heuristic only — not a substitute for a
   real security product`.

---

## Limitations & threat model

PhishGuard **does not**:

- **Fetch the URL.** It cannot see the actual HTML, can detect
  neither a login form behind a clean path nor a parked domain.
- **Resolve DNS.** A registered-but-unused domain will look just as
  "clean" as a live one.
- **Inspect certificates.** It won't notice a real cert mismatch or
  EV-cert details.
- **Run JavaScript.** It cannot detect client-side obfuscation,
  redirect chains, or fingerprinting scripts.
- **Use a blocklist.** It has no feed of *known-bad* URLs. It
  identifies *phishing-shaped* URLs, which is a different problem.
- **Whois / age.** A domain registered yesterday is a strong signal
  in real life; PhishGuard does not look it up.
- **Detect compromised legitimate domains.** A real bank URL serving
  a phishing page is invisible to this tool.
- **Decode Unicode tricks beyond ASCII homoglyphs.** E.g. zero-width
  joiners, RTL overrides, and confusable-script attacks beyond Cyrillic
  / Greek / fullwidth Latin are not covered.

**Threat model:** PhishGuard is designed to flag the *common, cheap*
phishing attempts — the misspelled brand domain, the KYC-scam SMS URL,
the free-DNS-hosted fake login page, the punycode look-alike, the
typosquat. It will **not** catch a sophisticated, well-resourced
attacker who registered `paypa1-login.com` three weeks ago and
hosted a pixel-perfect copy of PayPal.

Treat the score as a quick triage signal, not a verdict. When in
doubt, *do not click* — and use a real anti-phishing product, a
blocklist, and a fresh browser profile.

---

## Extending PhishGuard

### Add a brand

Open `brands.py` and add a tuple to the right category. Each entry is
`(canonical_name, [legit_domains])`.

```python
INDIAN_BANKS = [
    ...
    ("DBS Bank India",   ["dbs.com", "dbs.bank.in"]),
    ...
]
```

The module raises `ValueError` on import if you reuse a domain across
two brands, so duplicates are caught immediately. After adding,
restart `app.py` — the in-memory sets are rebuilt at import time.

If the canonical name is shorter or different from the registrable
domain (e.g. `onlinesbi.sbi` should display as `"SBI"`), add an
alias to the `BRAND_ALIAS` block near the bottom of `brands.py`.

### Add a suspicious keyword / TLD

Open `suspicious_lists.py` and append to the relevant list
(`SUSPICIOUS_TLDS`, `SUSPICIOUS_KEYWORDS`, `URL_SHORTENERS`,
`ABUSIVE_FREE_DNS`, `HIGH_RISK_COUNTRY_TLDS`, etc.). The lists are
plain Python `list`/`set` constants; no other code needs to change.

### Add a new heuristic

Open `detector.py`. The engine is one function — `analyze(url)` —
that walks the URL through each check, appending to a `flags` list
and adjusting a `score` integer. To add a new check, follow the
pattern of the existing ones:

```python
# inside analyze(), wherever fits your signal:
if your_condition(url):
    flags.append("your_flag_name")
    score -= 10  # your penalty
    if not reason:
        reason = "Plain-English explanation of what fired."
```

Run `python detector.py "https://example.com/"` to verify. If your
check needs new data, add it to `suspicious_lists.py` rather than
hard-coding it in the engine.

### Adjust the weights

All the penalties live as constants in `detector.py` near the top
of the file. The thresholds for `safe` / `likely_safe` /
`suspicious` / `fake` are at the very bottom of `analyze()`. Change
the numbers, restart the server, retest.

### Hook into another tool

`POST /api/check` is a plain JSON API. To plug PhishGuard into a
SIEM, mail filter, browser extension, or chat bot, POST every URL
you see and triage on `indicator` and `score`.

```python
import requests
r = requests.post("http://127.0.0.1:5000/api/check",
                  json={"url": "https://netf1ix.com"})
data = r.json()
if data["indicator"] in ("suspicious", "fake"):
    alert(data)
```

---

## License

This project is provided as-is for educational and demonstration
purposes. The brand list is a curated dataset assembled from
publicly visible information; trademark and brand names are the
property of their respective owners. The heuristic engine,
frontend, and dataset structure are released under the MIT license —
use them, fork them, ship them.
