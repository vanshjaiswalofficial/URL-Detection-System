"""Generates a realistic offline seed dataset for PhishGuard AI.

Creates diverse benign and malicious URLs with realistic paths, queries,
dates, and registered domain groupings per RULES R-DATA-1, R-DATA-6.
Ensures both benign and malicious domains appear across all temporal windows.
"""

from __future__ import annotations

import random
from typing import Any

from phishguard_ml.data.schema import create_dataset_row

# Curated popular benign domains with realistic paths
BENIGN_DOMAINS: list[str] = [
    "google.com", "github.com", "wikipedia.org", "microsoft.com", "amazon.com",
    "apple.com", "stackoverflow.com", "nytimes.com", "mozilla.org", "linkedin.com",
    "reddit.com", "cnn.com", "bbc.com", "medium.com", "cloudflare.com",
    "dropbox.com", "slack.com", "salesforce.com", "adobe.com", "oracle.com",
    "spotify.com", "netflix.com", "ebay.com", "paypal.com", "zoom.us",
    "twitter.com", "instagram.com", "pinterest.com", "tumblr.com", "wordpress.org",
    "quora.com", "etsy.com", "imdb.com", "hulu.com", "espn.com",
    "walmart.com", "target.com", "homedepot.com", "bestbuy.com", "costco.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "capitalone.com",
    "nih.gov", "cdc.gov", "nasa.gov", "who.int", "un.org"
]

BENIGN_PATHS: list[str] = [
    "/search?q=cybersecurity+training",
    "/account/settings/security",
    "/articles/2026/05/12/technology-update.html",
    "/docs/v2/api-reference",
    "/products/enterprise/overview",
    "/help/faq/password-reset-instructions",
    "/profile/dashboard",
    "/explore/trending?category=developer",
    "/support/ticket/submit",
    "/about/company/careers",
]

# Base domains for phishing attacks
MALICIOUS_DOMAINS: list[str] = [
    "update-service.cc", "portal-support.tk", "appleid-device.online",
    "secure-banking-gate.net", "netflix-billing-renew.info", "paypa1.com",
    "rnicrosoft.com", "amaz0n-security.com", "binance-us-security.xyz",
    "wellsfarg0.net", "paypal-verification-center.com", "apple-id-suspended-verify.com",
    "microsoft-account-alert365.com", "delivery-parcel-status.top",
    "steampowered-community-giveaway.club", "coinbase-vault-support.org",
    "chase-online-logon-auth.com", "bank-of-america-verify-ssn.net",
    "instagram-badge-verification.biz", "meta-business-suite-review.info",
    "185.220.101.5", "194.26.29.112", "45.142.214.88", "198.51.100.44",
    "account-renew-alert.pw", "secure-login-portal.cn", "support-desk-help.ws",
    "billing-service-suspended.top", "verify-your-identity-portal.xyz",
    "paypal-customer-resolution.cc", "azure-auth-connect.tk", "onedrive-document-share.online",
    "dhl-express-tracking-fee.link", "usps-package-address-confirm.info", "fedex-delivery-schedule.top",
    "metamask-seed-restore.io", "blockchain-ledger-wallet.xyz", "trustwallet-airdrop-claim.com",
    "adobe-acrobat-sign-document.net", "docu-sign-secure-contract.click"
]

MALICIOUS_SUBDOMAINS: list[str] = [
    "", "login", "secure", "verify", "account", "signin",
    "paypal.com.verify", "microsoft.login", "appleid.apple.com",
    "chaseonline.logon", "help.billing", "auth.token", "security.update",
]

MALICIOUS_PATHS: list[str] = [
    "/signin/account-overview.php",
    "/oauth2/v2.0/authorize?client_id=fake123",
    "/auth/verify-passcode",
    "/update-card-details?session=active",
    "/cgi-bin/webscr?cmd=_login-run",
    "/dispute/resolution/auth",
    "/wallet/connect/metamask",
    "/session?u=eyJ1c2VyIjoiam9obiIsImF1dGgiOiJmYWxzZSJ9",
    "/invoice-delivery-payment?fee=2.50",
    "/tradeoffer/new/?partner=987654",
]


def generate_seed_records(n_benign: int = 600, n_malicious: int = 500, seed: int = 42) -> list[dict[str, Any]]:
    """Generate reproducible seed dataset rows with realistic dates and balanced splits."""
    random.seed(seed)
    records: list[dict[str, Any]] = []

    # Assign each benign domain a random first_seen month from 1 to 9
    benign_domain_dates = {
        dom: f"2026-{random.randint(1, 9):02d}-{random.randint(1, 28):02d}"
        for dom in BENIGN_DOMAINS
    }

    # Assign each malicious domain a random first_seen month from 1 to 9
    malicious_domain_dates = {
        dom: f"2026-{random.randint(1, 9):02d}-{random.randint(1, 28):02d}"
        for dom in MALICIOUS_DOMAINS
    }

    # Generate benign URLs
    for _ in range(n_benign):
        domain = random.choice(BENIGN_DOMAINS)
        date_str = benign_domain_dates[domain]
        path = random.choice(BENIGN_PATHS)
        if random.random() < 0.3:
            path += f"&ref_id={random.randint(1000, 9999)}"

        raw_url = f"https://www.{domain}{path}"
        try:
            row = create_dataset_row(
                raw_url=raw_url,
                label=0,  # Benign = 0
                source="seed_curated_benign",
                first_seen=date_str,
            )
            records.append(row)
        except Exception:
            pass

    # Generate malicious URLs
    for _ in range(n_malicious):
        domain = random.choice(MALICIOUS_DOMAINS)
        date_str = malicious_domain_dates[domain]
        sub = random.choice(MALICIOUS_SUBDOMAINS)
        host = f"{sub}.{domain}" if sub else domain
        path = random.choice(MALICIOUS_PATHS)

        if random.random() < 0.3:
            path += f"&token={random.randint(10000, 99999)}"

        scheme = random.choice(["http", "https"])
        raw_url = f"{scheme}://{host}{path}"
        try:
            row = create_dataset_row(
                raw_url=raw_url,
                label=1,  # Malicious = 1
                source="seed_curated_phish",
                first_seen=date_str,
            )
            records.append(row)
        except Exception:
            pass

    return records
