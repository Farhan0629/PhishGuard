"""Suspicious-host and suspicious-URL signal tables used by the detector.

Everything is plain sets / dicts so it's easy to grow.
"""

# ---------------------------------------------------------------------------
#   SUSPICIOUS TLDs — heavily abused for phishing & scams
#   Source: PhishTank / Spamhaus / public abuse-feed aggregates.
# ---------------------------------------------------------------------------
SUSPICIOUS_TLDS = {
    # Cheap / free TLDs that get weaponized the most
    ".zip", ".mov", ".top", ".xyz", ".click", ".country", ".kim",
    ".work", ".review", ".support", ".bid", ".loan", ".win",
    ".stream", ".download", ".science", ".party", ".trade",
    ".accountant", ".faith", ".cricket", ".date", ".rest",
    ".mom", ".lol", ".fit", ".gdn", ".men", ".win", ".loan",
    ".cyou", ".icu", ".monster", ".bar", ".buzz", ".surf",
    ".quest", ".cam", ".sexy", ".skin", ".autos",
    # Free dynamic-DNS / sub-domain friendly TLDs
    ".tk", ".ml", ".ga", ".cf", ".gq",
    # Country-code TLDs with high abuse / weak registry controls
    ".ru", ".su", ".cn", ".pw", ".ws", ".cc", ".biz", ".info",
    ".cc", ".nu", ".tv", ".st", ".to", ".la", ".io", ".sh",
    ".sx", ".vg", ".ky", ".tc", ".ws", ".fm",
    # New TLDs known for abuse
    ".rest", ".mom", ".lol", ".fit", ".party", ".science",
    ".trade", ".date", ".faith", ".cricket", ".accountant",
    ".xyz", ".top", ".site", ".online", ".store", ".tech",
    ".app", ".dev", ".page", ".shop", ".club", ".live", ".vip",
    # Crypto / Web3 lure TLDs (over-sold but still useful signal)
    ".nft", ".wallet",
}

# ---------------------------------------------------------------------------
#   URL SHORTENERS — hide the real destination
# ---------------------------------------------------------------------------
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "t.co", "lnkd.in", "rebrand.ly", "cutt.ly", "shorturl.at",
    "rb.gy", "short.io", "v.gd", "t.ly", "soo.gd", "clck.ru",
    "qr.ae", "po.st", "mcaf.ee", "shorte.st", "adf.ly", "bc.vc",
    "tr.im", "snipurl.com", "ity.im", "doiop.com", "sh.st",
    "shorturl.com", "tiny.cc", "lnk.to", "bl.ink", "snip.ly",
    "short.cm", "t2m.io", "7.ly", "da.gd", "go2l.ink", "x.co",
    "urlz.fr", "url缩短.com", "v.ht", "urlbit.us", "lnk.bio",
    "u.to", "plu.sh", "sh.st", "qr.net", "sn.im", "gg.gg",
}

# ---------------------------------------------------------------------------
#   ABUSIVE FREE-DNS / HOSTING — legitimate services, very heavy abuse
# ---------------------------------------------------------------------------
ABUSIVE_FREE_DNS = {
    "servehttp.com", "serveftp.com", "redirectme.net", "dyndns.org",
    "duckdns.org", "hopto.org", "zapto.org", "no-ip.com", "no-ip.org",
    "ddns.net", "ddnsfree.com", "freedns.com", "afraid.org",
    "blogspot.com", "weebly.com", "wixsite.com", "000webhostapp.com",
    "github.io", "gitlab.io", "herokuapp.com", "appspot.com",
    "azurewebsites.net", "cloudapp.net", "azure-api.net",
    "ngrok.io", "ngrok-free.app", "telebit.cloud", "loca.lt",
    "wordpress.com", "weebly.com", "jimdosite.com", "webnode.com",
    "godaddysites.com", "site123.me", "webflow.io", "carrd.co",
    "framer.app", "framer.website", "typedream.app", "typedream.com",
    "notion.site", "ghost.io", "hashnode.com", "vercel.app",
    "netlify.app", "render.com", "onrender.com", "fly.dev",
    "repl.co", "replit.dev", "glitch.com", "surge.sh",
    "bitballoon.com", "strikingly.com", "bubbleapps.io",
    "myshopify.com", "bigcommerce.com", "squarespace.com",
    "wix.com", "web.app", "firebase.app", "amplifyapp.com",
    "elasticbeanstalk.com", "s3.amazonaws.com", "s3-website",
    "blob.core.windows.net", "googlecode.com", "codeberg.page",
    "sourceforge.net", "githack.com", "raw.githubusercontent.com",
}

# ---------------------------------------------------------------------------
#   FILE-HOSTING abused to deliver payloads
# ---------------------------------------------------------------------------
SUSPICIOUS_FILE_HOSTS = {
    "mediafire.com", "mega.nz", "mega.co.nz", "anonfiles.com",
    "transfer.sh", "0x0.st", "pastebin.com", "paste.mozilla.org",
    "gist.github.com", "ghostbin.com", "privatebin.net", "zerobin.net",
    "docdroid.net", "docdro.id", "pdfhost.io", "pdf-archive.com",
    "sendspace.com", "4shared.com", "zippyshare.com", "uploadfiles.io",
    "dropbox.com", "drive.google.com", "docs.google.com",
}

# ---------------------------------------------------------------------------
#   PATH / QUERY KEYWORDS — high-signal words for phishing URLs
# ---------------------------------------------------------------------------
SUSPICIOUS_KEYWORDS = {
    # credential / account takeover
    "login": 10, "log-in": 10, "signin": 8, "sign-in": 8,
    "logon": 8, "auth": 6, "authenticate": 6, "session": 6,
    "verify": 10, "verification": 8, "validate": 6, "confirm": 6,
    "update": 8, "reactivate": 10, "unlock": 10, "restore": 6,
    "secure": 8, "security": 6, "account": 8, "profile": 4,
    "recover": 6, "recovery": 6, "access": 4, "activate": 8,
    # financial bait
    "bank": 10, "banking": 10, "wallet": 8, "pay": 6, "payment": 6,
    "invoice": 6, "billing": 6, "refund": 8, "transfer": 6,
    "bonus": 6, "reward": 6, "gift": 4, "prize": 6, "claim": 6,
    "crypto": 8, "bitcoin": 8, "ethereum": 8, "usdt": 6,
    "transaction": 6, "deposit": 6, "withdraw": 6, "wire": 4,
    "settlement": 4, "tax": 6, "taxes": 6, "payment-update": 8,
    # password / reset
    "password": 10, "passwd": 10, "pwd": 8, "reset": 6,
    # package / delivery lures
    "delivery": 6, "shipment": 6, "tracking": 4, "parcel": 4,
    "fedex": 4, "dhl": 4, "usps": 4, "ups": 4,
    "redelivery": 8, "customs": 4, "import-duty": 8, "package": 4,
    # tax / government lures
    "irs": 6, "tax": 6, "refund-status": 6, "hmrc": 6,
    "stimulus": 4, "rebate": 4, "outstanding": 4,
    # tech-support lures
    "support": 4, "helpdesk": 6, "service": 4, "alert": 6,
    "warning": 4, "notice": 4, "suspended": 10, "limited": 4,
    "fraud": 8, "compromised": 10, "unauthorized": 10,
    "tech-support": 8, "virus": 6, "malware": 8, "infected": 8,
    # Microsoft / Apple / Google themed
    "apple-id": 10, "icloud-login": 10, "icloud-support": 10,
    "outlook-login": 10, "office365": 8, "onedrive": 6,
    "gmail-support": 10, "google-verify": 10, "play-store": 4,
    # Action lures
    "click": 4, "here": 1, "urgent": 8, "immediate": 6, "now": 1,
    # Crypto specific
    "seed": 8, "seed-phrase": 10, "private-key": 10, "metamask": 8,
    "trust-wallet": 8, "ledger-support": 8, "trezor": 6,
    "connect-wallet": 8, "approve": 6, "mint": 4, "airdrop": 6,
    "nft-drop": 8, "whitelist": 6, "presale": 6, "claim-airdrop": 10,
    # Banking specifics
    "kyc": 6, "kyc-update": 8, "aml": 4, "swift": 4, "iban": 4,
    # Romance / scam
    "inheritance": 8, "beneficiary": 6, "donation": 6, "charity": 4,
    "lottery": 8, "winner": 6, "jackpot": 8, "congratulations": 6,
    # Covid / health / benefits (recurring lures)
    "covid": 4, "vaccine": 4, "covid-vaccine": 8, "health-pass": 8,
    "covid-test": 6, "boosters": 4, "covid-aid": 6,
    # Document themed
    "doc": 2, "document": 2, "view": 2, "open": 2, "review": 4,
    "download": 4, "shared": 4, "shared-doc": 8, "secure-doc": 10,
    "secure-attach": 10, "secure-msg": 10, "secure-portal": 10,
    "encrypted": 4, "vault": 6, "portal": 4,
    # Generic account / action verbs that phishers love
    "reactivate-account": 12, "verify-account": 12, "secure-account": 12,
    "update-payment": 10, "update-billing": 10, "payment-failed": 10,
    "billing-alert": 10, "invoice-attached": 8, "statement": 4,
    "e-statement": 8, "balance": 2, "overdue": 6, "past-due": 6,
    "subscription": 4, "renewal": 4, "renew": 4, "expiry": 4,
    "expire": 4, "expired": 4, "card-on-file": 8,
    # Common shorteners people type (helps catch lookalikes)
    "bit.ly": 4, "tinyurl": 4, "t.co": 4, "is.gd": 4, "ow.ly": 4,
    "rb.gy": 4, "cutt.ly": 4, "shorturl": 4, "rebrand.ly": 4,
    # Romance / gift card / advance-fee
    "gift-card": 8, "steam-gift": 8, "google-play-card": 8,
    "itunes-card": 8, "amazon-card": 8, "wire-transfer": 8,
    "western-union": 8, "moneygram": 6,
    # Survey / prize
    "survey": 4, "free-gift": 8, "free-iphone": 10, "free-trial": 4,
    "free": 1, "trial": 1, "winner-announcement": 10,
}

# ---------------------------------------------------------------------------
#   QUERY-STRING PARAMETER red-flags (very high signal when present)
# ---------------------------------------------------------------------------
SUSPICIOUS_QUERY_PARAMS = {
    "redirect", "redir", "url", "next", "return", "returnTo",
    "return_to", "continue", "goto", "destination", "target",
    "login", "signin", "auth", "token", "session", "phpsessid",
    "ref", "refid", "aff", "affiliate", "tracking",
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
}

# ---------------------------------------------------------------------------
#   HIGH-RISK PATH PATTERNS — regex that flags structured phishing paths
# ---------------------------------------------------------------------------
SUSPICIOUS_PATH_PATTERNS = [
    r"/login\b",
    r"/signin\b",
    r"/verify\b",
    r"/verify-account\b",
    r"/account-verify\b",
    r"/secure-login\b",
    r"/secure-portal\b",
    r"/wallet/connect\b",
    r"/wallet/import\b",
    r"/wallet/recover\b",
    r"/airdrop/claim\b",
    r"/auth/2fa\b",
    r"/reset-password\b",
    r"/forgot-password\b",
    r"/update-billing\b",
    r"/payment-method\b",
    r"/session-expired\b",
    r"/account-suspended\b",
    r"/kyc/verify\b",
    r"/kyc/update\b",
    r"/mfa/enroll\b",
    r"/mfa/verify\b",
    r"/oauth/authorize\b",
    r"/oauth/callback\b",
    r"/connect/[\w-]+/auth\b",
    r"/api/v\d+/login\b",
    r"\.php\?.*?(login|signin|verify|account|password|auth)\b",
    r"/cgi-bin/.*\.(cgi|pl|exe|sh|py|rb)\b",
    r"\.(exe|msi|apk|dmg|scr|jar|bat|cmd|vbs|ps1|iso|img|js|hta|cpl|wsf)\b",
]

# Country-code TLDs commonly used by attackers to *appear* local in
# target countries, even when the actual infrastructure is elsewhere.
HIGH_RISK_COUNTRY_TLDS = {
    # Eastern Europe / former Soviet
    ".ru", ".su", ".ua", ".by", ".kz",
    # Asia
    ".cn", ".hk", ".tw", ".mo", ".vn", ".id", ".ph", ".my", ".th",
    # Africa
    ".ng", ".za", ".ke",
    # South America
    ".ve", ".br",
}

# TLDs that map to Western / low-risk countries — used to *lightly* offset
# penalties so a French bank's actual customer-facing portal on .fr doesn't
# get crushed by the suspicious TLD list.
LOW_RISK_COUNTRY_TLDS = {
    ".fr", ".de", ".it", ".es", ".nl", ".be", ".ch", ".at", ".se",
    ".no", ".dk", ".fi", ".ie", ".pt", ".pl", ".cz", ".gr", ".hu",
    ".jp", ".kr", ".sg", ".au", ".nz", ".ca", ".uk", ".co.uk", ".gov.uk",
    ".gov", ".mil", ".edu", ".ca", ".ie", ".lu",
}
