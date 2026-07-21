"""Brand impersonation lookup.

The detector compares every URL's registrable domain against the legitimate
domains below. The list is organized by category (financial, tech, retail,
delivery, social, gaming, crypto, gov/tax, dev/infra) so it's easy to grow.

Each entry: (canonical_brand_name, [legitimate_domains]).
"""

# ---------------------------------------------------------------------------
#   TECH / CONSUMER
# ---------------------------------------------------------------------------
TECH = [
    ("Microsoft",       ["microsoft.com", "live.com", "outlook.com", "office.com",
                         "office365.com", "msn.com", "azure.com", "bing.com",
                         "xbox.com", "skype.com", "microsoftonline.com",
                         "login.microsoftonline.com", "account.microsoft.com",
                         "support.microsoft.com"]),
    ("Apple",           ["apple.com", "icloud.com", "me.com", "appleid.apple.com"]),
    ("Google",          ["google.com", "gmail.com", "googlemail.com", "youtube.com",
                         "drive.google.com", "docs.google.com", "android.com",
                         "chromium.org"]),
    ("Meta",            ["facebook.com", "fb.com", "meta.com", "messenger.com",
                         "whatsapp.com", "oculus.com"]),
    ("Amazon",          ["amazon.com", "amazon.co.uk", "amazon.in", "amazon.de",
                         "amazonaws.com", "amazon.ca", "amazon.com.au",
                         "amazon.com.mx", "amazon.com.br", "amazon.es",
                         "amazon.fr", "amazon.it", "amazon.nl", "amazon.sg",
                         "amazon.sa", "amazon.ae", "amazon.eg", "amazon.se",
                         "amazon.pl", "amazon.co.jp"]),
    ("Netflix",         ["netflix.com"]),
    ("eBay",            ["ebay.com", "ebayimg.com", "ebaystatic.com"]),
    ("PayPal",          ["paypal.com", "paypal-corp.com"]),
    ("Stripe",          ["stripe.com"]),
    ("Dropbox",         ["dropbox.com", "dropboxbusiness.com"]),
    ("Adobe",           ["adobe.com", "acrobat.adobe.com", "adobelogin.com"]),
    ("Docusign",        ["docusign.com", "docusign.net"]),
    ("Atlassian",       ["atlassian.com", "jira.atlassian.com",
                         "bitbucket.org", "trello.com", "statuspage.io"]),
    ("Slack",           ["slack.com"]),
    ("Zoom",            ["zoom.us", "zoom.com"]),
    ("Cisco",           ["cisco.com", "webex.com", "meraki.com"]),
    ("VMware",          ["vmware.com"]),
    ("Oracle",          ["oracle.com"]),
    ("SAP",             ["sap.com"]),
    ("Salesforce",      ["salesforce.com", "force.com"]),
    ("ServiceNow",      ["servicenow.com"]),
    ("Workday",         ["workday.com"]),
    ("Intuit",          ["intuit.com", "turbotax.com", "quickbooks.com",
                         "mint.com", "creditkarma.com"]),
    ("Mailchimp",       ["mailchimp.com"]),
    ("Zendesk",         ["zendesk.com"]),
    ("Box",             ["box.com"]),
    ("Proton",          ["proton.me", "protonmail.com", "protonvpn.com"]),
    ("Tutanota",        ["tuta.com", "tutanota.com"]),
    ("Yandex",          ["yandex.com", "yandex.ru", "yandex.net"]),
    ("Baidu",           ["baidu.com"]),
    ("Naver",           ["naver.com"]),
    ("Roku",            ["roku.com"]),
    ("Sonos",           ["sonos.com"]),
    ("Bose",            ["bose.com"]),
    ("Canon",           ["canon.com", "usa.canon.com"]),
    ("Nikon",           ["nikon.com"]),
    ("GoPro",           ["gopro.com"]),
    ("DJI",             ["dji.com"]),
]

# ---------------------------------------------------------------------------
#   SOCIAL / COMMS
# ---------------------------------------------------------------------------
SOCIAL = [
    ("Twitter",         ["twitter.com", "x.com", "t.co"]),
    ("LinkedIn",        ["linkedin.com", "lnkd.in"]),
    ("Instagram",       ["instagram.com"]),
    ("Snapchat",        ["snapchat.com", "snap.com"]),
    ("TikTok",          ["tiktok.com"]),
    ("Pinterest",       ["pinterest.com", "pinimg.com"]),
    ("Reddit",          ["reddit.com", "redd.it"]),
    ("Tumblr",          ["tumblr.com"]),
    ("Discord",         ["discord.com", "discord.gg", "discordapp.com"]),
    ("Telegram",        ["telegram.org", "telegram.me", "t.me", "telegra.ph"]),
    ("WeChat",          ["wechat.com", "weixin.qq.com"]),
    ("Signal",          ["signal.org"]),
    ("Teams",           ["teams.microsoft.com", "teams.live.com"]),
    ("Mastodon",        ["mastodon.social", "joinmastodon.org"]),
    ("Threads",         ["threads.net"]),
    ("Bluesky",         ["bsky.app", "bsky.social"]),
    ("Vimeo",           ["vimeo.com"]),
    ("Twitch",          ["twitch.tv"]),
    ("Kick",            ["kick.com"]),
    ("Quora",           ["quora.com"]),
    ("Medium",          ["medium.com"]),
    ("Substack",        ["substack.com"]),
]

# ---------------------------------------------------------------------------
#   EMAIL / OAUTH
# ---------------------------------------------------------------------------
EMAIL = [
    ("Yahoo",           ["yahoo.com", "ymail.com", "rocketmail.com",
                         "yahoo.co.uk"]),
    ("GMX",             ["gmx.com", "gmx.net", "gmx.de"]),
    ("AOL",             ["aol.com", "aim.com"]),
    ("Zoho",            ["zoho.com", "zohomail.com"]),
    ("Fastmail",        ["fastmail.com", "fastmail.fm"]),
]

# ---------------------------------------------------------------------------
#   FINANCIAL / BANKING
# ---------------------------------------------------------------------------
FINANCE = [
    ("Bank of America", ["bankofamerica.com"]),
    ("Wells Fargo",     ["wellsfargo.com"]),
    ("Chase",           ["chase.com"]),
    ("Citibank",        ["citi.com", "citibank.com", "citigroup.com"]),
    ("HSBC",            ["hsbc.com", "hsbc.co.uk"]),
    ("Barclays",        ["barclays.com", "barclays.co.uk"]),
    ("Santander",       ["santander.com", "santander.co.uk"]),
    ("Lloyds",          ["lloydsbank.com", "lloydsbankinggroup.com"]),
    ("NatWest",         ["natwest.com", "rbs.co.uk"]),
    ("TD Bank",         ["td.com", "tdbank.com"]),
    ("Capital One",     ["capitalone.com"]),
    ("PNC",             ["pnc.com"]),
    ("US Bank",         ["usbank.com"]),
    ("Fifth Third",     ["53.com"]),
    ("Discover",        ["discover.com", "discovercard.com"]),
    ("American Express", ["americanexpress.com", "amex.com", "aexp.com"]),
    ("Visa",            ["visa.com"]),
    ("Mastercard",      ["mastercard.com"]),
    ("Fidelity",        ["fidelity.com"]),
    ("Charles Schwab",  ["schwab.com"]),
    ("Vanguard",        ["vanguard.com"]),
    ("TD Ameritrade",   ["tdameritrade.com"]),
    ("E*Trade",         ["etrade.com"]),
    ("Robinhood",       ["robinhood.com"]),
    ("Revolut",         ["revolut.com"]),
    ("N26",             ["n26.com"]),
    ("Monzo",           ["monzo.com"]),
    ("Starling",        ["starlingbank.com"]),
    ("ING",             ["ing.com", "ing.nl"]),
    ("Deutsche Bank",   ["db.com", "deutschebank.de"]),
    ("UBS",             ["ubs.com"]),
    ("Credit Suisse",   ["credit-suisse.com"]),
    ("Standard Chartered", ["sc.com"]),
    ("RBC",             ["rbc.com", "rbcroyalbank.com"]),
    ("Scotiabank",      ["scotiabank.com"]),
    ("BMO",             ["bmo.com"]),
    ("CIBC",            ["cibc.com"]),
    ("Desjardins",      ["desjardins.com"]),
    ("ANZ",             ["anz.com", "anz.co.nz"]),
    ("Westpac",         ["westpac.com.au"]),
    ("Commonwealth Bank", ["commbank.com.au", "cba.com.au"]),
    ("NAB",             ["nab.com.au"]),
]

# ---------------------------------------------------------------------------
#   CRYPTO / WEB3
# ---------------------------------------------------------------------------
CRYPTO = [
    ("Coinbase",        ["coinbase.com", "pro.coinbase.com"]),
    ("Binance",         ["binance.com", "binance.us", "bnb.com"]),
    ("Kraken",          ["kraken.com"]),
    ("Crypto.com",      ["crypto.com"]),
    ("Bitfinex",        ["bitfinex.com"]),
    ("Bitstamp",        ["bitstamp.net"]),
    ("Gemini",          ["gemini.com"]),
    ("KuCoin",          ["kucoin.com"]),
    ("OKX",             ["okx.com", "okex.com"]),
    ("Bybit",           ["bybit.com"]),
    ("Huobi",           ["huobi.com", "htx.com"]),
    ("Gate.io",         ["gate.io", "gate.com"]),
    ("MEXC",            ["mexc.com"]),
    ("Bitget",          ["bitget.com"]),
    ("MetaMask",        ["metamask.io", "metamask.com"]),
    ("Trust Wallet",    ["trustwallet.com"]),
    ("Phantom",         ["phantom.app"]),
    ("Exodus",          ["exodus.com"]),
    ("Electrum",        ["electrum.org"]),
    ("Ledger",          ["ledger.com"]),
    ("Trezor",          ["trezor.io"]),
    ("BitPay",          ["bitpay.com"]),
    ("OpenSea",         ["opensea.io"]),
    ("Rarible",         ["rarible.com"]),
    ("Binance NFT",     ["nft.binance.com"]),
    ("Uniswap",         ["uniswap.org", "app.uniswap.org"]),
    ("PancakeSwap",     ["pancakeswap.finance", "pancake.finance"]),
    ("Ethereum",        ["ethereum.org"]),
    ("Bitcoin",         ["bitcoin.org"]),
    ("Solana",          ["solana.com"]),
    ("Polygon",         ["polygon.technology", "polygon.com"]),
    ("Avalanche",       ["avax.network"]),
]

# ---------------------------------------------------------------------------
#   RETAIL / ECOMMERCE
# ---------------------------------------------------------------------------
RETAIL = [
    ("Walmart",         ["walmart.com"]),
    ("Target",          ["target.com"]),
    ("Costco",          ["costco.com"]),
    ("Best Buy",        ["bestbuy.com"]),
    ("Home Depot",      ["homedepot.com"]),
    ("Lowe's",          ["lowes.com"]),
    ("IKEA",            ["ikea.com"]),
    ("Macy's",          ["macys.com"]),
    ("Nordstrom",       ["nordstrom.com"]),
    ("Sephora",         ["sephora.com"]),
    ("Ulta",            ["ulta.com"]),
    ("Etsy",            ["etsy.com"]),
    ("Alibaba",         ["alibaba.com", "aliexpress.com", "taobao.com",
                         "tmall.com", "1688.com"]),
    ("Shein",           ["shein.com", "sheingroup.com"]),
    ("Temu",            ["temu.com"]),
    ("Zara",            ["zara.com"]),
    ("H&M",             ["hm.com"]),
    ("Nike",            ["nike.com"]),
    ("Adidas",          ["adidas.com", "adidas-group.com"]),
    ("New Balance",     ["newbalance.com"]),
    ("Lululemon",       ["lululemon.com"]),
    ("Wayfair",         ["wayfair.com"]),
    ("Booking",         ["booking.com"]),
    ("Expedia",         ["expedia.com"]),
    ("Airbnb",          ["airbnb.com"]),
    ("Uber",            ["uber.com"]),
    ("Lyft",            ["lyft.com"]),
    ("DoorDash",        ["doordash.com"]),
    ("Instacart",       ["instacart.com"]),
    ("Grubhub",         ["grubhub.com"]),
    ("Postmates",       ["postmates.com"]),
    ("StubHub",         ["stubhub.com"]),
    ("Ticketmaster",    ["ticketmaster.com", "livenation.com"]),
    ("Shopify",         ["shopify.com", "myshopify.com"]),
    ("Square",          ["squareup.com", "square.com", "block.com"]),
    ("Klarna",          ["klarna.com"]),
    ("Afterpay",        ["afterpay.com"]),
]

# ---------------------------------------------------------------------------
#   DELIVERY / LOGISTICS
# ---------------------------------------------------------------------------
DELIVERY = [
    ("DHL",             ["dhl.com", "dhl.de"]),
    ("FedEx",           ["fedex.com"]),
    ("UPS",             ["ups.com"]),
    ("USPS",            ["usps.com"]),
    ("Royal Mail",      ["royalmail.com"]),
    ("Canada Post",     ["canadapost.ca"]),
    ("Australia Post",  ["auspost.com.au"]),
    ("La Poste",        ["laposte.fr"]),
    ("Deutsche Post",   ["deutschepost.de"]),
    ("Yodel",           ["yodel.co.uk"]),
    ("Hermes",          ["myhermes.co.uk", "evri.com"]),
    ("Aramex",          ["aramex.com"]),
    ("TNT",             ["tnt.com"]),
    ("SF Express",      ["sf-express.com"]),
    ("YTO",             ["yto.net.cn"]),
    ("JD Logistics",    ["jd.com", "jdl.com"]),
    ("Lalamove",        ["lalamove.com"]),
    ("Maersk",          ["maersk.com"]),
    ("MSC",             ["msc.com"]),
    ("CMA CGM",         ["cma-cgm.com"]),
]

# ---------------------------------------------------------------------------
#   TRAVEL / HOSPITALITY
# ---------------------------------------------------------------------------
TRAVEL = [
    ("Delta",           ["delta.com"]),
    ("United",          ["united.com"]),
    ("American Airlines", ["aa.com", "americanairlines.com"]),
    ("Southwest",       ["southwest.com"]),
    ("JetBlue",         ["jetblue.com"]),
    ("Spirit",          ["spirit.com"]),
    ("Frontier",        ["flyfrontier.com"]),
    ("Alaska Airlines", ["alaskaair.com"]),
    ("Lufthansa",       ["lufthansa.com"]),
    ("British Airways", ["britishairways.com"]),
    ("Air France",      ["airfrance.com"]),
    ("KLM",             ["klm.com"]),
    ("Emirates",        ["emirates.com"]),
    ("Qatar Airways",   ["qatarairways.com"]),
    ("Etihad",          ["etihad.com"]),
    ("Singapore Airlines", ["singaporeair.com"]),
    ("Cathay Pacific",  ["cathaypacific.com"]),
    ("Qantas",          ["qantas.com", "qantas.com.au"]),
    ("Air Canada",      ["aircanada.com"]),
    ("Marriott",        ["marriott.com", "bonvoy.com"]),
    ("Hilton",          ["hilton.com"]),
    ("Hyatt",           ["hyatt.com"]),
    ("IHG",             ["ihg.com"]),
    ("Choice",          ["choicehotels.com"]),
    ("Wyndham",         ["wyndhamhotels.com"]),
    ("Best Western",    ["bestwestern.com"]),
    ("Vrbo",            ["vrbo.com"]),
    ("Hotels.com",      ["hotels.com"]),
    ("Trivago",         ["trivago.com"]),
    ("Kayak",           ["kayak.com"]),
    ("Skyscanner",      ["skyscanner.com"]),
    ("Hopper",          ["hopper.com"]),
    ("Tripadvisor",     ["tripadvisor.com"]),
]

# ---------------------------------------------------------------------------
#   HEALTHCARE / INSURANCE
# ---------------------------------------------------------------------------
HEALTH = [
    ("UnitedHealth",    ["unitedhealthgroup.com", "unitedhealthcare.com",
                         "optum.com"]),
    ("Anthem",          ["anthem.com"]),
    ("Aetna",           ["aetna.com"]),
    ("Cigna",           ["cigna.com"]),
    ("Humana",          ["humana.com"]),
    ("Kaiser",          ["kp.org", "kaiserpermanente.org"]),
    ("Blue Cross",      ["bcbs.com"]),
    ("Cleveland Clinic", ["my.clevelandclinic.org"]),
    ("Mayo Clinic",     ["mayoclinic.org"]),
    ("Johns Hopkins",   ["hopkinsmedicine.org"]),
    ("CVS",             ["cvs.com"]),
    ("Walgreens",       ["walgreens.com"]),
    ("Rite Aid",        ["riteaid.com"]),
    ("GoodRx",          ["goodrx.com"]),
    ("WebMD",           ["webmd.com"]),
    ("Zocdoc",          ["zocdoc.com"]),
    ("Teladoc",         ["teladoc.com"]),
]

# ---------------------------------------------------------------------------
#   GAMING / ENTERTAINMENT
# ---------------------------------------------------------------------------
GAMING = [
    ("Steam",           ["steampowered.com", "steamcommunity.com", "store.steampowered.com"]),
    ("Epic Games",      ["epicgames.com", "fortnite.com", "unrealengine.com"]),
    ("Roblox",          ["roblox.com"]),
    ("Minecraft",       ["minecraft.net", "mojang.com"]),
    ("EA",              ["ea.com", "electronicarts.com"]),
    ("Ubisoft",         ["ubisoft.com", "ubi.com"]),
    ("Activision",      ["activision.com", "callofduty.com", "blizzard.com"]),
    ("PlayStation",     ["playstation.com", "sony.com", "sonyinteractive.com"]),
    ("Nintendo",        ["nintendo.com", "nintendo.co.jp"]),
    ("Riot Games",      ["riotgames.com", "leagueoflegends.com"]),
    ("Spotify",         ["spotify.com"]),
    ("Deezer",          ["deezer.com"]),
    ("SoundCloud",      ["soundcloud.com"]),
    ("Tidal",           ["tidal.com"]),
    ("Pandora",         ["pandora.com"]),
    ("Audible",         ["audible.com", "audible.co.uk"]),
    ("Hulu",            ["hulu.com"]),
    ("Disney Plus",     ["disneyplus.com", "disney.com"]),
    ("HBO Max",         ["hbomax.com", "max.com", "warnerbros.com"]),
    ("Paramount Plus",  ["paramountplus.com", "paramount.com"]),
    ("Peacock",         ["peacocktv.com", "nbcuniversal.com"]),
    ("Crunchyroll",     ["crunchyroll.com"]),
    ("Funimation",      ["funimation.com"]),
]

# ---------------------------------------------------------------------------
#   GOV / TAX
# ---------------------------------------------------------------------------
GOV = [
    ("IRS",             ["irs.gov"]),
    ("HMRC",            ["gov.uk", "hmrc.gov.uk"]),
    ("CRA",             ["canada.ca", "cra-arc.gc.ca"]),
    ("ATO",             ["ato.gov.au"]),
    ("Inland Revenue NZ", ["ird.govt.nz"]),
    ("Social Security", ["ssa.gov"]),
    ("Medicare",        ["medicare.gov"]),
    ("DMV",             ["dmv.com", "dmv.org"]),
    ("FTC",             ["ftc.gov"]),
    ("FBI",             ["fbi.gov"]),
    ("ICE",             ["ice.gov"]),
    ("Court",           ["uscourts.gov"]),
    ("Census",          ["census.gov"]),
    ("Health",          ["health.gov", "cdc.gov", "who.int", "nih.gov"]),
    ("FDA",             ["fda.gov"]),
    ("NHS",             ["nhs.uk"]),
    ("MyGov",           ["my.gov.au"]),
]

# ---------------------------------------------------------------------------
#   DEVELOPER / INFRA
# ---------------------------------------------------------------------------
DEV = [
    ("GitHub",          ["github.com", "github.io", "githubusercontent.com"]),
    ("GitLab",          ["gitlab.com", "gitlab.io"]),
    ("GCP",             ["cloud.google.com", "googleapis.com", "googleusercontent.com"]),
    ("Cloudflare",      ["cloudflare.com", "cloudflare-dns.com", "1.1.1.1"]),
    ("Fastly",          ["fastly.com", "fastly.net"]),
    ("Akamai",          ["akamai.com", "akamaiedge.net", "akamaihd.net"]),
    ("DigitalOcean",    ["digitalocean.com"]),
    ("Linode",          ["linode.com"]),
    ("Vultr",           ["vultr.com"]),
    ("Heroku",          ["heroku.com", "herokuapp.com"]),
    ("Vercel",          ["vercel.com", "now.sh"]),
    ("Netlify",         ["netlify.com", "netlify.app"]),
    ("Render",          ["render.com", "onrender.com"]),
    ("Fly.io",          ["fly.io"]),
    ("Supabase",        ["supabase.com", "supabase.co"]),
    ("Firebase",        ["firebase.google.com", "firebaseapp.com"]),
    ("NPM",             ["npmjs.com"]),
    ("PyPI",            ["pypi.org", "python.org"]),
    ("Docker Hub",      ["hub.docker.com", "docker.com"]),
    ("OpenAI",          ["openai.com", "chatgpt.com", "chat.openai.com"]),
    ("Anthropic",       ["anthropic.com"]),
    ("Google AI",       ["ai.google", "deepmind.com", "gemini.google.com"]),
    ("HuggingFace",     ["huggingface.co"]),
    ("Replicate",       ["replicate.com"]),
    ("Twilio",          ["twilio.com"]),
    ("SendGrid",        ["sendgrid.com"]),
    ("Okta",            ["okta.com"]),
    ("Auth0",           ["auth0.com"]),
    ("1Password",       ["1password.com"]),
    ("Bitwarden",       ["bitwarden.com", "bitwarden.eu"]),
    ("LastPass",        ["lastpass.com"]),
    ("Dashlane",        ["dashlane.com"]),
    ("Norton",          ["norton.com", "nortonlifelock.com"]),
    ("McAfee",          ["mcafee.com"]),
    ("Avast",           ["avast.com"]),
    ("AVG",             ["avg.com"]),
    ("Kaspersky",       ["kaspersky.com", "kaspersky.ru"]),
    ("Bitdefender",     ["bitdefender.com"]),
    ("ESET",            ["eset.com"]),
    ("Malwarebytes",    ["malwarebytes.com"]),
    ("Trend Micro",     ["trendmicro.com"]),
    ("Sophos",          ["sophos.com"]),
    ("F-Secure",        ["f-secure.com"]),
]

# ---------------------------------------------------------------------------
#   INDIAN BANKS  (high-priority phishing target)
# ---------------------------------------------------------------------------
INDIAN_BANKS = [
    ("SBI",              ["sbi.co.in", "onlinesbi.com", "onlinesbi.sbi"]),
    ("HDFC Bank",        ["hdfcbank.com"]),
    ("ICICI Bank",       ["icicibank.com"]),
    ("Axis Bank",        ["axisbank.com"]),
    ("Punjab National Bank", ["pnbindia.in", "pnbindia.com"]),
    ("Bank of Baroda",   ["bankofbaroda.in", "bobibanking.com", "bob.in"]),
    ("Union Bank",       ["unionbankofindia.co.in", "epayments.unionbankofindia.co.in"]),
    ("Canara Bank",      ["canarabank.com"]),
    ("Indian Bank",      ["indianbank.co.in", "indianbank.in"]),
    ("IDFC FIRST Bank",  ["idfcfirstbank.com"]),
    ("Kotak Mahindra",   ["kotak.com"]),
    ("Yes Bank",         ["yesbank.in"]),
    ("IndusInd",         ["indusind.com"]),
    ("AU Small Finance Bank", ["aubank.in"]),
    ("Federal Bank",     ["federalbank.co.in"]),
    ("UCO Bank",         ["ucobank.com"]),
    ("Central Bank of India", ["centralbankofindia.co.in"]),
    ("South Indian Bank", ["sib.co.in"]),
    ("Karnataka Bank",   ["karnatakabank.com"]),
    ("Bandhan Bank",     ["bandhanbank.com"]),
    ("RBL Bank",         ["rblbank.com"]),
    ("City Union Bank",  ["cityunionbank.com"]),
    ("Bank of India",    ["bankofindia.co.in"]),
]

# ---------------------------------------------------------------------------
#   UPI / PAYMENT APPS  (top impersonation target in India)
# ---------------------------------------------------------------------------
UPI = [
    ("PhonePe",          ["phonepe.com"]),
    ("Google Pay India", ["pay.google.com", "gpay.app", "tez.google.com"]),
    ("Paytm",            ["paytm.com"]),
    ("BHIM",             ["bhimupi.org.in", "upi.npci.org.in"]),
    ("Amazon Pay India", ["amazonpay.in"]),
    ("Mobikwik",         ["mobikwik.com"]),
    ("Freecharge",       ["freecharge.in"]),
    ("Razorpay",         ["razorpay.com"]),
    ("Cashfree",         ["cashfree.com"]),
    ("CRED",             ["cred.club", "cred.com"]),
    ("BharatPe",         ["bharatpe.com"]),
    ("Pine Labs",        ["pinelabs.com"]),
    ("Juspay",           ["juspay.in", "juspay.com"]),
]

# ---------------------------------------------------------------------------
#   INDIAN GOVERNMENT PORTALS  (massive phishing target)
# ---------------------------------------------------------------------------
INDIAN_GOV = [
    ("UIDAI",            ["uidai.gov.in"]),
    ("DigiLocker",       ["digilocker.gov.in"]),
    ("UMANG",            ["umang.gov.in"]),
    ("Income Tax",       ["incometax.gov.in", "incometaxindia.gov.in"]),
    ("GST Portal",       ["gst.gov.in"]),
    ("EPFO",             ["epfindia.gov.in", "epfo.gov.in", "unifiedportal-mem.epfindia.gov.in"]),
    ("NPCI",             ["npci.org.in"]),
    ("Passport Seva",    ["passportindia.gov.in"]),
    ("MCA",              ["mca.gov.in"]),
    ("PM Kisan",         ["pmkisan.gov.in"]),
    ("PM Jan Dhan",      ["pmjdy.gov.in"]),
    ("CoWIN",            ["cowin.gov.in"]),
    ("National Scholarship Portal",
                        ["scholarships.gov.in"]),
    ("JEE Main",         ["jeemain.nta.nic.in"]),
    ("NTA",              ["nta.ac.in"]),
    ("UPSC",             ["upsc.gov.in"]),
    ("SSC",              ["ssc.nic.in", "ssc.gov.in"]),
    ("IRCTC",            ["irctc.co.in"]),
    ("GeM",              ["gem.gov.in"]),
    ("MyGov India",      ["mygov.gov.in"]),
]

# ---------------------------------------------------------------------------
#   INDIAN E-COMMERCE
# ---------------------------------------------------------------------------
INDIAN_ECOMMERCE = [
    ("Flipkart",         ["flipkart.com"]),
    ("Myntra",           ["myntra.com"]),
    ("Meesho",           ["meesho.com"]),
    ("AJIO",             ["ajio.com"]),
    ("Nykaa",            ["nykaa.com", "nykaafashion.com"]),
    ("Tata CliQ",        ["tatacliq.com"]),
    ("Snapdeal",         ["snapdeal.com"]),
    ("JioMart",          ["jiomart.com"]),
    ("FirstCry",         ["firstcry.com"]),
    ("Pepperfry",        ["pepperfry.com"]),
    ("Reliance Digital", ["reliancedigital.in"]),
    ("Croma",            ["croma.com"]),
    ("Vijay Sales",      ["vijaysales.com"]),
]

# ---------------------------------------------------------------------------
#   INDIAN TELECOM  (fake recharge links)
# ---------------------------------------------------------------------------
INDIAN_TELECOM = [
    ("Jio",              ["jio.com", "myjio.com", "ril.com"]),
    ("Airtel",           ["airtel.in", "airtel.com"]),
    ("Vi",               ["myvi.in", "vilpower.in", "vodafone.in"]),
    ("BSNL",             ["bsnl.co.in"]),
    ("MTNL",             ["mtnl.in"]),
]

# ---------------------------------------------------------------------------
#   INDIAN DELIVERY / LOGISTICS
# ---------------------------------------------------------------------------
INDIAN_DELIVERY = [
    ("India Post",       ["indiapost.gov.in"]),
    ("Delhivery",        ["delhivery.com"]),
    ("Blue Dart",        ["bluedart.com"]),
    ("DTDC",             ["dtdc.in", "dtdc.com"]),
    ("XpressBees",       ["xpressbees.com"]),
    ("Shadowfax",        ["shadowfax.in"]),
    ("Ecom Express",     ["ecomexpress.in"]),
    ("Ekart",            ["ekartlogistics.com", "ekart.in"]),
    ("Porter",           ["porter.in"]),
]

# ---------------------------------------------------------------------------
#   INDIAN TRAVEL
# ---------------------------------------------------------------------------
INDIAN_TRAVEL = [
    ("MakeMyTrip",       ["makemytrip.com"]),
    ("Goibibo",          ["goibibo.com"]),
    ("Yatra",            ["yatra.com"]),
    ("EaseMyTrip",       ["easemytrip.com", "easemytrip.in"]),
    ("RedBus",           ["redbus.in", "redbus.com"]),
    ("AbhiBus",          ["abhibus.com"]),
    ("ConfirmTkt",       ["confirmtkt.com"]),
    ("Ixigo",            ["ixigo.com"]),
    ("Cleartrip",        ["cleartrip.com"]),
]

# ---------------------------------------------------------------------------
#   INDIAN FOOD DELIVERY
# ---------------------------------------------------------------------------
INDIAN_FOOD = [
    ("Zomato",           ["zomato.com"]),
    ("Swiggy",           ["swiggy.com"]),
    ("Blinkit",          ["blinkit.com", "grofers.com"]),
    ("Zepto",            ["zepto.com"]),
    ("BigBasket",        ["bigbasket.com"]),
    ("Instamart",        ["instamart.com"]),
]

# ---------------------------------------------------------------------------
#   INDIAN INSURANCE
# ---------------------------------------------------------------------------
INDIAN_INSURANCE = [
    ("LIC",              ["lic.in", "lic.in.in"]),
    ("SBI Life",         ["sbilife.co.in"]),
    ("HDFC Life",        ["hdfclife.com"]),
    ("ICICI Prudential", ["iciciprulife.com"]),
    ("Tata AIA",         ["tataaia.com"]),
    ("Max Life",         ["maxlifeinsurance.com"]),
    ("Bajaj Allianz",    ["bajajallianzlife.com", "bajajallianzgeneral.com"]),
    ("Star Health",      ["starhealth.in"]),
    ("Niva Bupa",        ["nivabupa.com"]),
    ("Care Health",      ["careinsurance.com"]),
]

# ---------------------------------------------------------------------------
#   INDIAN INVESTMENT / BROKING
# ---------------------------------------------------------------------------
INDIAN_INVESTMENT = [
    ("Groww",            ["groww.in", "groww.com"]),
    ("Zerodha",          ["zerodha.com", "kite.zerodha.com"]),
    ("Angel One",        ["angelone.in", "angelbroking.com"]),
    ("Upstox",           ["upstox.com"]),
    ("5Paisa",           ["5paisa.com"]),
    ("Paytm Money",      ["paytmmoney.com"]),
    ("INDmoney",         ["indmoney.com"]),
    ("ET Money",         ["etmoney.com"]),
    ("Kuvera",           ["kuvera.in"]),
    ("Motilal Oswal",    ["motilaloswal.com"]),
]

# ---------------------------------------------------------------------------
#   INDIAN EDUCATION
# ---------------------------------------------------------------------------
INDIAN_EDUCATION = [
    ("Coursera",         ["coursera.org"]),
    ("Udemy",            ["udemy.com"]),
    ("Unacademy",        ["unacademy.com"]),
    ("BYJU'S",           ["byjus.com", "byjus.in", "byju.com"]),
    ("Vedantu",          ["vedantu.com"]),
    ("Physics Wallah",   ["pw.live", "physicswallah.com"]),
    ("Khan Academy",     ["khanacademy.org"]),
    ("NPTEL",            ["nptel.ac.in"]),
    ("SWAYAM",           ["swayam.gov.in", "swayam2.ac.in"]),
]

# ---------------------------------------------------------------------------
#   INDIAN OTT
# ---------------------------------------------------------------------------
INDIAN_OTT = [
    ("JioHotstar",       ["jiohotstar.com", "hotstar.com"]),
    ("Sony LIV",         ["sonyliv.com"]),
    ("Zee5",             ["zee5.com"]),
    ("JioCinema",        ["jiocinema.com"]),
    ("Amazon Prime Video", ["primevideo.com"]),
    ("Apple TV+",        ["tv.apple.com"]),
    ("MX Player",        ["mxplayer.in", "mxplayer.com"]),
]

# ---------------------------------------------------------------------------
#   INDIAN UTILITIES  (bill-payment scams)
# ---------------------------------------------------------------------------
INDIAN_UTILITIES = [
    ("WBSEDCL",          ["wbsedcl.in"]),
    ("CESC",             ["cesc.co.in"]),
    ("Tata Power",       ["tatapower.com", "tatapowerddl.com"]),
    ("Adani Electricity", ["adani electricity.com", "adanielectricity.com"]),
    ("BESCOM",           ["bescom.org", "bescom.in"]),
    ("MSEB",             ["msebindia.org", "mahadiscom.in"]),
    ("UPPCL",            ["uppcl.org", "uppclonline.com"]),
]

# ---------------------------------------------------------------------------
#   INDIAN GAS
# ---------------------------------------------------------------------------
INDIAN_GAS = [
    ("Indane",           ["indfreel.co.in", "indianoil.co.in", "iocl.com"]),
    ("Bharat Gas",       ["bharatpetroleum.in", "bharatgas.in", "bharatpetroleum.com"]),
    ("HP Gas",           ["hplpg.in", "hpcl.co.in", "hindustanpetroleum.com"]),
]

# ---------------------------------------------------------------------------
#   INDIAN CRYPTO EXCHANGES
# ---------------------------------------------------------------------------
INDIAN_CRYPTO = [
    ("CoinDCX",          ["coindcx.com"]),
    ("CoinSwitch",       ["coinswitch.co", "coinswitch.com", "coinswitch.kuber.com"]),
    ("Mudrex",           ["mudrex.com"]),
    ("Giottus",          ["giottus.com"]),
    ("WazirX",           ["wazirx.com"]),
]

# ---------------------------------------------------------------------------
#   CLOUD / AI TOOLS  (rising AI-phishing surface)
# ---------------------------------------------------------------------------
CLOUD_AI = [
    ("Perplexity",       ["perplexity.ai"]),
    ("Claude",           ["claude.ai"]),
    ("Grok",             ["grok.com", "x.ai"]),
    ("Cursor",           ["cursor.sh", "cursor.com"]),
    ("Windsurf",         ["codeium.com", "windsurf.com"]),
    ("Replit",           ["replit.com", "repl.it"]),
    ("Lovable",          ["lovable.dev", "lovable.so"]),
    ("Bolt.new",         ["bolt.new", "stackblitz.com"]),
]

# ---------------------------------------------------------------------------
#   Aggregated list — every category combined
# ---------------------------------------------------------------------------
BRANDS = (
    TECH + SOCIAL + EMAIL + FINANCE + CRYPTO + RETAIL
    + DELIVERY + TRAVEL + HEALTH + GAMING + GOV + DEV
    + INDIAN_BANKS + UPI + INDIAN_GOV + INDIAN_ECOMMERCE
    + INDIAN_TELECOM + INDIAN_DELIVERY + INDIAN_TRAVEL
    + INDIAN_FOOD + INDIAN_INSURANCE + INDIAN_INVESTMENT
    + INDIAN_EDUCATION + INDIAN_OTT + INDIAN_UTILITIES
    + INDIAN_GAS + INDIAN_CRYPTO + CLOUD_AI
)

# Sanity: assert no duplicate brand names OR legit domains.
_seen_names = set()
_seen_domains = set()
for _name, _domains in BRANDS:
    if _name in _seen_names:
        raise ValueError(f"duplicate brand entry: {_name}")
    _seen_names.add(_name)
    for d in _domains:
        if d in _seen_domains:
            raise ValueError(f"legit domain {d!r} is listed under more than one brand")
        _seen_domains.add(d)

# Build the public lookup tables.
LEGITIMATE_DOMAINS = set()
DOMAIN_TO_BRAND = {}
for _name, _domains in BRANDS:
    for d in _domains:
        d = d.lower()
        LEGITIMATE_DOMAINS.add(d)
        # First brand wins if a domain is shared (rare).
        DOMAIN_TO_BRAND.setdefault(d, _name)

# A short alias table: useful for showing the public name in the UI when
# the registrable domain maps to a sub-brand.
BRAND_ALIAS = {
    "appleid.apple.com": "Apple",
    "drive.google.com": "Google",
    "docs.google.com": "Google",
    "android.com": "Google",
    "chromium.org": "Google",
    "outlook.live.com": "Microsoft",
    "teams.microsoft.com": "Microsoft",
    "teams.live.com": "Microsoft",
    "messenger.com": "Meta",
    "oculus.com": "Meta",
    "ebayimg.com": "eBay",
    "ebaystatic.com": "eBay",
    "paypal-corp.com": "PayPal",
    "acrobat.adobe.com": "Adobe",
    "adobelogin.com": "Adobe",
    "jira.atlassian.com": "Atlassian",
    "trello.com": "Atlassian",
    "statuspage.io": "Atlassian",
    "webex.com": "Cisco",
    "meraki.com": "Cisco",
    "force.com": "Salesforce",
    "turbotax.com": "Intuit",
    "quickbooks.com": "Intuit",
    "mint.com": "Intuit",
    "creditkarma.com": "Intuit",
    "protonvpn.com": "Proton",
    "usa.canon.com": "Canon",
    "lnkd.in": "LinkedIn",
    "t.co": "Twitter",
    "redd.it": "Reddit",
    "discord.gg": "Discord",
    "discordapp.com": "Discord",
    "t.me": "Telegram",
    "telegra.ph": "Telegram",
    "weixin.qq.com": "WeChat",
    "wa.me": "WhatsApp",
    "aim.com": "AOL",
    "zohomail.com": "Zoho",
    "fastmail.fm": "Fastmail",
    "me.com": "Apple",
    "hotmail.com": "Outlook",
    "ymail.com": "Yahoo",
    "rocketmail.com": "Yahoo",
    "yahoo.co.uk": "Yahoo",
    "citi.com": "Citibank",
    "citigroup.com": "Citibank",
    "hsbc.co.uk": "HSBC",
    "barclays.co.uk": "Barclays",
    "lloydsbank.com": "Lloyds",
    "lloydsbankinggroup.com": "Lloyds",
    "rbs.co.uk": "NatWest",
    "td.com": "TD Bank",
    "tdbank.com": "TD Bank",
    "aexp.com": "American Express",
    "bonvoy.com": "Marriott",
    "santander.co.uk": "Santander",
    "rbcroyalbank.com": "RBC",
    "anz.co.nz": "ANZ",
    "anz.com.au": "ANZ",
    "commbank.com.au": "Commonwealth Bank",
    "cba.com.au": "Commonwealth Bank",
    "qantas.com.au": "Qantas",
    "pro.coinbase.com": "Coinbase",
    "binance.us": "Binance",
    "bnb.com": "Binance",
    "okex.com": "OKX",
    "htx.com": "Huobi",
    "gate.com": "Gate.io",
    "metamask.com": "MetaMask",
    "phantom.app": "Phantom",
    "electrum.org": "Electrum",
    "trezor.io": "Trezor",
    "opensea.io": "OpenSea",
    "app.uniswap.org": "Uniswap",
    "pancakeswap.finance": "PancakeSwap",
    "pancake.finance": "PancakeSwap",
    "ethereum.org": "Ethereum",
    "bitcoin.org": "Bitcoin",
    "solana.com": "Solana",
    "polygon.technology": "Polygon",
    "polygon.com": "Polygon",
    "avax.network": "Avalanche",
    "aliexpress.com": "Alibaba",
    "aliyun.com": "Alibaba",
    "taobao.com": "Alibaba",
    "tmall.com": "Alibaba",
    "1688.com": "Alibaba",
    "sheingroup.com": "Shein",
    "adidas-group.com": "Adidas",
    "myshopify.com": "Shopify",
    "squareup.com": "Square",
    "square.com": "Square",
    "block.com": "Square",
    "livenation.com": "Ticketmaster",
    "dhl.de": "DHL",
    "canadapost.ca": "Canada Post",
    "auspost.com.au": "Australia Post",
    "laposte.fr": "La Poste",
    "deutschepost.de": "Deutsche Post",
    "yodel.co.uk": "Yodel",
    "myhermes.co.uk": "Hermes",
    "evri.com": "Evri",
    "sf-express.com": "SF Express",
    "yto.net.cn": "YTO",
    "jd.com": "JD Logistics",
    "jdl.com": "JD Logistics",
    "lalamove.com": "Lalamove",
    "maersk.com": "Maersk",
    "msc.com": "MSC",
    "cma-cgm.com": "CMA CGM",
    "aa.com": "American Airlines",
    "americanairlines.com": "American Airlines",
    "flyfrontier.com": "Frontier",
    "alaskaair.com": "Alaska Airlines",
    "britishairways.com": "British Airways",
    "qatarairways.com": "Qatar Airways",
    "singaporeair.com": "Singapore Airlines",
    "cathaypacific.com": "Cathay Pacific",
    "aircanada.com": "Air Canada",
    "wyndhamhotels.com": "Wyndham",
    "bestwestern.com": "Best Western",
    "choicehotels.com": "Choice",
    "unitedhealthgroup.com": "UnitedHealth",
    "unitedhealthcare.com": "UnitedHealth",
    "optum.com": "UnitedHealth",
    "kp.org": "Kaiser",
    "kaiserpermanente.org": "Kaiser",
    "bcbs.com": "Blue Cross",
    "my.clevelandclinic.org": "Cleveland Clinic",
    "mayoclinic.org": "Mayo Clinic",
    "hopkinsmedicine.org": "Johns Hopkins",
    "goodrx.com": "GoodRx",
    "teladoc.com": "Teladoc",
    "zocdoc.com": "Zocdoc",
    "webmd.com": "WebMD",
    "fortnite.com": "Epic Games",
    "unrealengine.com": "Epic Games",
    "mojang.com": "Minecraft",
    "electronicarts.com": "EA",
    "ubi.com": "Ubisoft",
    "callofduty.com": "Activision",
    "battle.net": "Activision",
    "sony.com": "PlayStation",
    "sonyinteractive.com": "PlayStation",
    "nintendo.co.jp": "Nintendo",
    "leagueoflegends.com": "Riot Games",
    "audible.co.uk": "Audible",
    "hbomax.com": "HBO Max",
    "max.com": "HBO Max",
    "warnerbros.com": "HBO Max",
    "paramountplus.com": "Paramount Plus",
    "paramount.com": "Paramount Plus",
    "peacocktv.com": "Peacock",
    "nbcuniversal.com": "Peacock",
    "disney.com": "Disney Plus",
    "disneyplus.com": "Disney Plus",
    "tidal.com": "Tidal",
    "pandora.com": "Pandora",
    "deezer.com": "Deezer",
    "soundcloud.com": "SoundCloud",
    "bitcoin.org": "Bitcoin",
    "ethereum.org": "Ethereum",
    "solana.com": "Solana",
    "polygon.technology": "Polygon",
    "hmrc.gov.uk": "HMRC",
    "cra-arc.gc.ca": "CRA",
    "ato.gov.au": "ATO",
    "ird.govt.nz": "Inland Revenue NZ",
    "medicare.gov": "Medicare",
    "ssa.gov": "Social Security",
    "ftc.gov": "FTC",
    "fbi.gov": "FBI",
    "ice.gov": "ICE",
    "uscourts.gov": "Court",
    "census.gov": "Census",
    "health.gov": "Health",
    "cdc.gov": "Health",
    "who.int": "Health",
    "nih.gov": "Health",
    "nhs.uk": "NHS",
    "dwp.gov.uk": "DWP",
    "my.gov.au": "MyGov",
    "amazon.co.uk": "Amazon",
    "amazon.in": "Amazon",
    "amazon.de": "Amazon",
    "amazon.ca": "Amazon",
    "amazon.com.au": "Amazon",
    "amazon.com.mx": "Amazon",
    "amazon.com.br": "Amazon",
    "amazon.es": "Amazon",
    "amazon.fr": "Amazon",
    "amazon.it": "Amazon",
    "amazon.nl": "Amazon",
    "amazon.sg": "Amazon",
    "amazon.sa": "Amazon",
    "amazon.ae": "Amazon",
    "amazon.eg": "Amazon",
    "amazon.se": "Amazon",
    "amazon.pl": "Amazon",
    "amazon.co.jp": "Amazon",
    "amazonaws.com": "Amazon",
    "azure.com": "Microsoft",
    "bing.com": "Microsoft",
    "xbox.com": "Microsoft",
    "skype.com": "Microsoft",
    "googlemail.com": "Google",
    "youtube.com": "Google",
    "outlook.com": "Microsoft",
    "live.com": "Microsoft",
    "office.com": "Microsoft",
    "office365.com": "Microsoft",
    "msn.com": "Microsoft",
    "azurewebsites.net": "Azure",
    "cloudflare-dns.com": "Cloudflare",
    "fastly.net": "Fastly",
    "akamaiedge.net": "Akamai",
    "akamaihd.net": "Akamai",
    "onrender.com": "Render",
    "fly.io": "Fly.io",
    "supabase.co": "Supabase",
    "firebaseapp.com": "Firebase",
    "github.io": "GitHub",
    "githubusercontent.com": "GitHub",
    "gitlab.io": "GitLab",
    "aws.amazon.com": "AWS",
    "googleapis.com": "GCP",
    "googleusercontent.com": "GCP",
    "cloud.google.com": "GCP",
    "herokuapp.com": "Heroku",
    "now.sh": "Vercel",
    "netlify.app": "Netlify",
    "vercel.com": "Vercel",
    "openai.com": "OpenAI",
    "chatgpt.com": "OpenAI",
    "chat.openai.com": "OpenAI",
    "anthropic.com": "Anthropic",
    "ai.google": "Google AI",
    "deepmind.com": "Google AI",
    "gemini.google.com": "Google AI",
    "huggingface.co": "HuggingFace",
    "replicate.com": "Replicate",
    "auth0.com": "Auth0",
    "1password.com": "1Password",
    "bitwarden.eu": "Bitwarden",
    "nortonlifelock.com": "Norton",
    "kaspersky.ru": "Kaspersky",
    "robux.com": "Roblox",

    # ---- INDIAN BANKS ----
    "onlinesbi.com": "SBI",
    "onlinesbi.sbi": "SBI",
    "sbi.co.in": "SBI",
    "hdfcbank.com": "HDFC Bank",
    "icicibank.com": "ICICI Bank",
    "axisbank.com": "Axis Bank",
    "pnbindia.in": "Punjab National Bank",
    "pnbindia.com": "Punjab National Bank",
    "bankofbaroda.in": "Bank of Baroda",
    "bobibanking.com": "Bank of Baroda",
    "bob.in": "Bank of Baroda",
    "unionbankofindia.co.in": "Union Bank",
    "epayments.unionbankofindia.co.in": "Union Bank",
    "canarabank.com": "Canara Bank",
    "indianbank.co.in": "Indian Bank",
    "indianbank.in": "Indian Bank",
    "idfcfirstbank.com": "IDFC FIRST Bank",
    "kotak.com": "Kotak Mahindra",
    "yesbank.in": "Yes Bank",
    "indusind.com": "IndusInd",
    "aubank.in": "AU Small Finance Bank",
    "federalbank.co.in": "Federal Bank",
    "ucobank.com": "UCO Bank",
    "centralbankofindia.co.in": "Central Bank of India",
    "sib.co.in": "South Indian Bank",
    "karnatakabank.com": "Karnataka Bank",
    "bandhanbank.com": "Bandhan Bank",
    "rblbank.com": "RBL Bank",
    "cityunionbank.com": "City Union Bank",
    "bankofindia.co.in": "Bank of India",

    # ---- UPI / PAYMENT ----
    "phonepe.com": "PhonePe",
    "pay.google.com": "Google Pay India",
    "gpay.app": "Google Pay India",
    "tez.google.com": "Google Pay India",
    "paytm.com": "Paytm",
    "paytmmoney.com": "Paytm",
    "bhimupi.org.in": "BHIM",
    "upi.npci.org.in": "BHIM",
    "npci.org.in": "NPCI",
    "amazon.in": "Amazon",
    "amazonpay.in": "Amazon Pay India",
    "mobikwik.com": "Mobikwik",
    "freecharge.in": "Freecharge",
    "razorpay.com": "Razorpay",
    "cashfree.com": "Cashfree",
    "cred.club": "CRED",
    "cred.com": "CRED",
    "bharatpe.com": "BharatPe",
    "pinelabs.com": "Pine Labs",
    "juspay.in": "Juspay",
    "juspay.com": "Juspay",

    # ---- INDIAN GOV ----
    "uidai.gov.in": "UIDAI",
    "digilocker.gov.in": "DigiLocker",
    "umang.gov.in": "UMANG",
    "incometax.gov.in": "Income Tax",
    "incometaxindia.gov.in": "Income Tax",
    "gst.gov.in": "GST Portal",
    "epfindia.gov.in": "EPFO",
    "epfo.gov.in": "EPFO",
    "unifiedportal-mem.epfindia.gov.in": "EPFO",
    "passportindia.gov.in": "Passport Seva",
    "mca.gov.in": "MCA",
    "pmkisan.gov.in": "PM Kisan",
    "pmjdy.gov.in": "PM Jan Dhan",
    "cowin.gov.in": "CoWIN",
    "scholarships.gov.in": "National Scholarship Portal",
    "jeemain.nta.nic.in": "JEE Main",
    "nta.ac.in": "NTA",
    "upsc.gov.in": "UPSC",
    "ssc.nic.in": "SSC",
    "ssc.gov.in": "SSC",
    "irctc.co.in": "IRCTC",
    "gem.gov.in": "GeM",
    "mygov.gov.in": "MyGov India",

    # ---- INDIAN E-COMMERCE ----
    "flipkart.com": "Flipkart",
    "myntra.com": "Myntra",
    "meesho.com": "Meesho",
    "ajio.com": "AJIO",
    "nykaa.com": "Nykaa",
    "nykaafashion.com": "Nykaa",
    "tatacliq.com": "Tata CliQ",
    "snapdeal.com": "Snapdeal",
    "jiomart.com": "JioMart",
    "firstcry.com": "FirstCry",
    "pepperfry.com": "Pepperfry",
    "reliancedigital.in": "Reliance Digital",
    "croma.com": "Croma",
    "vijaysales.com": "Vijay Sales",

    # ---- INDIAN TELECOM ----
    "jio.com": "Jio",
    "myjio.com": "Jio",
    "ril.com": "Jio",
    "airtel.in": "Airtel",
    "airtel.com": "Airtel",
    "myvi.in": "Vi",
    "vilpower.in": "Vi",
    "vodafone.in": "Vi",
    "bsnl.co.in": "BSNL",
    "mtnl.in": "MTNL",

    # ---- INDIAN DELIVERY ----
    "indiapost.gov.in": "India Post",
    "delhivery.com": "Delhivery",
    "bluedart.com": "Blue Dart",
    "dtdc.in": "DTDC",
    "dtdc.com": "DTDC",
    "xpressbees.com": "XpressBees",
    "shadowfax.in": "Shadowfax",
    "ecomexpress.in": "Ecom Express",
    "ekartlogistics.com": "Ekart",
    "ekart.in": "Ekart",
    "porter.in": "Porter",

    # ---- INDIAN TRAVEL ----
    "makemytrip.com": "MakeMyTrip",
    "goibibo.com": "Goibibo",
    "yatra.com": "Yatra",
    "easemytrip.com": "EaseMyTrip",
    "easemytrip.in": "EaseMyTrip",
    "redbus.in": "RedBus",
    "redbus.com": "RedBus",
    "abhibus.com": "AbhiBus",
    "confirmtkt.com": "ConfirmTkt",
    "ixigo.com": "Ixigo",
    "cleartrip.com": "Cleartrip",

    # ---- INDIAN FOOD ----
    "zomato.com": "Zomato",
    "swiggy.com": "Swiggy",
    "blinkit.com": "Blinkit",
    "grofers.com": "Blinkit",
    "zepto.com": "Zepto",
    "bigbasket.com": "BigBasket",
    "instamart.com": "Swiggy",

    # ---- INDIAN INSURANCE ----
    "lic.in": "LIC",
    "lic.in.in": "LIC",
    "sbilife.co.in": "SBI Life",
    "hdfclife.com": "HDFC Life",
    "iciciprulife.com": "ICICI Prudential",
    "tataaia.com": "Tata AIA",
    "maxlifeinsurance.com": "Max Life",
    "bajajallianzlife.com": "Bajaj Allianz",
    "bajajallianzgeneral.com": "Bajaj Allianz",
    "starhealth.in": "Star Health",
    "nivabupa.com": "Niva Bupa",
    "careinsurance.com": "Care Health",

    # ---- INDIAN INVESTMENT ----
    "groww.in": "Groww",
    "groww.com": "Groww",
    "zerodha.com": "Zerodha",
    "kite.zerodha.com": "Zerodha",
    "angelone.in": "Angel One",
    "angelbroking.com": "Angel One",
    "upstox.com": "Upstox",
    "5paisa.com": "5Paisa",
    "indmoney.com": "INDmoney",
    "etmoney.com": "ET Money",
    "kuvera.in": "Kuvera",
    "motilaloswal.com": "Motilal Oswal",

    # ---- INDIAN EDUCATION ----
    "coursera.org": "Coursera",
    "udemy.com": "Udemy",
    "unacademy.com": "Unacademy",
    "byjus.com": "BYJU'S",
    "byjus.in": "BYJU'S",
    "byju.com": "BYJU'S",
    "vedantu.com": "Vedantu",
    "pw.live": "Physics Wallah",
    "physicswallah.com": "Physics Wallah",
    "khanacademy.org": "Khan Academy",
    "nptel.ac.in": "NPTEL",
    "swayam.gov.in": "SWAYAM",
    "swayam2.ac.in": "SWAYAM",

    # ---- INDIAN OTT ----
    "jiohotstar.com": "JioHotstar",
    "hotstar.com": "JioHotstar",
    "sonyliv.com": "Sony LIV",
    "zee5.com": "Zee5",
    "jiocinema.com": "JioCinema",
    "primevideo.com": "Amazon Prime Video",
    "mxplayer.in": "MX Player",
    "mxplayer.com": "MX Player",

    # ---- INDIAN UTILITIES ----
    "wbsedcl.in": "WBSEDCL",
    "cesc.co.in": "CESC",
    "tatapower.com": "Tata Power",
    "tatapowerddl.com": "Tata Power",
    "adani electricity.com": "Adani Electricity",
    "adanielectricity.com": "Adani Electricity",
    "bescom.org": "BESCOM",
    "bescom.in": "BESCOM",
    "msebindia.org": "MSEB",
    "mahadiscom.in": "MSEB",
    "uppcl.org": "UPPCL",
    "uppclonline.com": "UPPCL",

    # ---- INDIAN GAS ----
    "indfreel.co.in": "Indane",
    "indianoil.co.in": "Indane",
    "iocl.com": "Indane",
    "bharatpetroleum.in": "Bharat Gas",
    "bharatgas.in": "Bharat Gas",
    "bharatpetroleum.com": "Bharat Gas",
    "hplpg.in": "HP Gas",
    "hpcl.co.in": "HP Gas",
    "hindustanpetroleum.com": "HP Gas",

    # ---- INDIAN CRYPTO ----
    "coindcx.com": "CoinDCX",
    "coinswitch.co": "CoinSwitch",
    "coinswitch.com": "CoinSwitch",
    "coinswitch.kuber.com": "CoinSwitch",
    "mudrex.com": "Mudrex",
    "giottus.com": "Giottus",
    "wazirx.com": "WazirX",

    # ---- CLOUD / AI ----
    "perplexity.ai": "Perplexity",
    "claude.ai": "Claude",
    "grok.com": "Grok",
    "x.ai": "Grok",
    "cursor.sh": "Cursor",
    "cursor.com": "Cursor",
    "codeium.com": "Windsurf",
    "windsurf.com": "Windsurf",
    "replit.com": "Replit",
    "repl.it": "Replit",
    "lovable.dev": "Lovable",
    "lovable.so": "Lovable",
    "bolt.new": "Bolt.new",
    "stackblitz.com": "Bolt.new",
}
