"""Product name and personal-use copy. One place so the UI and attestation agree."""

NAME = "Kerf"
SLUG = "kerf"
TAGLINE = "authorized web security"
CA_CN = "Kerf Root CA"
ACCOUNTS_EMAIL = "accounts@kerf.software"
LICENSE_NAME = "Kerf Personal Use License"
COPYRIGHT = "Copyright © 2026 Smashrock Media Inc. All rights reserved."
ATTEST_VERSION = 2

LICENSE_TERMS = (
    "Personal, non-commercial use only, on systems you own or are authorized to test.",
    "No commercial use — paid work, an employer, a client, or any commercial advantage.",
    "No redistribution — including commercial redistribution, public forks, mirrors, bundling, or hosting Kerf as a service.",
)

ATTESTATION = (
    "I have read and accept the Kerf Personal Use License. "
    "I will use Kerf only for personal, non-commercial purposes on systems "
    "I own or am authorized to test. I will not use Kerf for paid work, an "
    "employer, a client, or any commercial advantage. I will not redistribute "
    "Kerf, including any commercial redistribution."
)

PLANS = {
    "personal": {
        "label": "Personal",
        "price": "Free",
        "blurb": "Personal use only. No commercial use, no redistribution.",
        "features": [
            "Proxy, intercept, Replay, History",
            "Capture, crawler, Endpoints, local and hosted OAST",
            "Payloads and Scan (authorized scope)",
            "Evidence vault, lockfile watch, BYO or hosted AI",
            f"Commercial license: email {ACCOUNTS_EMAIL}",
        ],
    },
}


def catalog() -> list:
    return [{"id": k, **v} for k, v in PLANS.items()]
