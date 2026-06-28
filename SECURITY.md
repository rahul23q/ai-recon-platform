# Security Policy

## Authorized use only

`recon-platform` is a security **reconnaissance** tool. Use it only against
systems you own or are **explicitly authorized in writing** to test.
Unauthorized scanning is illegal in most jurisdictions and is not a supported
use of this project. The default profile performs *passive* reconnaissance, and
an authorization gate (`RECON_AUTHORIZED_ONLY`, `RECON_AUTHORIZED_TARGETS`)
guards against accidental out-of-scope activity.

## Reporting a vulnerability

If you discover a security vulnerability **in this codebase** (not in a target
you scanned), please report it privately:

1. **Do not** open a public issue for undisclosed vulnerabilities.
2. Use GitHub's **private vulnerability reporting** (Security → *Report a
   vulnerability*) on this repository, or contact the maintainers directly.
3. Include: affected version/commit, reproduction steps, impact, and any PoC.

We aim to acknowledge reports within **5 business days** and to provide a
remediation timeline after triage. Coordinated disclosure is appreciated.

## Scope

In scope: bugs in this repository that could lead to credential exposure,
remote code execution, SSRF via the recon modules, injection, or bypass of the
authorization gate.

Out of scope: findings produced *by* the tool about third-party targets, and
issues in optional third-party dependencies (report those upstream).

## Handling of sensitive data

- No secrets are committed to this repository. Configuration (including
  `ANTHROPIC_API_KEY`) is provided at runtime via environment variables or a
  local, git-ignored `.env` file.
- Recon output (`reports/`, `runs/`) is git-ignored and may contain sensitive
  information about authorized targets — handle and store it accordingly.
