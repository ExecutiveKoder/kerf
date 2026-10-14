# Security, authorization, and responsible use

## Authorization is a precondition, not a suggestion

SureGuard intercepts and can replay HTTP/HTTPS traffic. Run it only against:

- systems you own, or
- systems you have **explicit, written permission** to test (a signed scope /
  rules of engagement, a bug-bounty program's in-scope list, etc.).

Intercepting traffic you're not party to, or probing systems you don't control,
may violate laws including the US Computer Fraud and Abuse Act, Canada's Criminal
Code (s. 342.1), the UK Computer Misuse Act, and equivalents elsewhere. The MIT
license disclaims liability; it does not grant you permission to test anything.

## How TLS interception works here (and its limits)

The proxy generates a local root CA. For each HTTPS host, it mints a leaf
certificate signed by that CA. Interception only works for clients that **trust
your CA**, i.e. browsers/devices you have configured on a machine you control.
The CA cannot be used to intercept anyone else's traffic, and it does not weaken
real certificate validation for anyone who hasn't installed it.

Keep the CA private key (`~/.dastday/ca-key.pem`) safe. Anyone with it can
mint certificates your trust store will accept. The file is created mode 0600 on
POSIX systems. Remove the CA from your trust store when you're done testing.

## Scope enforcement

Use the **Scope** feature to list in-scope hosts. The active-scan engine
(operator-supplied checks only) refuses to run with an empty scope and only
touches hosts you have explicitly authorized via `authorize_scope()`.

## What this project will not ship

- Bundled attack payloads or exploit-confirmation logic for the active scanner.
- Any check that writes to or damages a target as a "test".

Those are left to operators for authorized engagements. See
[WRITING_ACTIVE_CHECKS.md](WRITING_ACTIVE_CHECKS.md).

## Reporting a vulnerability in this tool

If you find a security issue in SureGuard itself, open a private advisory on
the project's repository rather than a public issue.
