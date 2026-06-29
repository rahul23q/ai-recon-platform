"""Cross-source verification (Phase 3.1).

Pure, framework-agnostic logic that corroborates passive-recon observations
against the Browser agent's in-browser observations before they become findings.
The goal is to make a whole class of false positives impossible: a security
header reported "missing" by a passive HTTP fetch (which many servers only send
to browser-like requests) is only confirmed missing when an independent source
agrees — otherwise it is downgraded, or flagged as a false positive.

The logic here is deliberately import-light (only domain types) so it is trivially
testable and reusable by both the :class:`~recon_platform.agents.verification.VerificationAgent`
and the Analysis agent.
"""
