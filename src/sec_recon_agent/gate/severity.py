"""Severity derivation from OSV's raw severity token.

OSV surfaces severity as the upstream-authored score string verbatim: almost
always a CVSS vector (v2 vectors are bare "AV:N/...", v3/v4 carry a
"CVSS:3.x/" / "CVSS:4.0/" prefix), occasionally a plain numeric score. The
base score is computed deterministically from the vector via the `cvss`
library (RedHatProductSecurity), then banded with the NVD qualitative cuts
(`agent/ssvc.py::band_for_score`, shared with the triage path).
Anything unparseable yields (None, None) - the SSVC decision still works
(Act/Attend are KEV/EPSS/exploit-driven; only the severity-based Track* rung
loses signal) and the SARIF just omits security-severity for that rule.
"""

from decimal import Decimal

from cvss import CVSS2, CVSS3, CVSS4, CVSSError

from sec_recon_agent.agent.schema import Severity

# Banding is shared with the agent path's evidence-derived severity signal so
# a CVSS score lands in the same qualitative band whichever path scored it.
from sec_recon_agent.agent.ssvc import band_for_score

__all__ = ["band_for_score", "severity_from_token"]


def _base_score(token: str) -> float | None:
    if token.startswith("CVSS:4"):
        raw = CVSS4(token).base_score
    elif token.startswith("CVSS:3"):
        raw = CVSS3(token).base_score
    elif token.startswith(("AV:", "(AV:")):
        # CVSS v2 vectors carry no version prefix; the parenthesized form is
        # NVD's historical serialization.
        raw = CVSS2(token.strip("()")).base_score
    else:
        try:
            raw = Decimal(token)
        except ArithmeticError:
            return None
    score = float(raw)
    if not 0.0 <= score <= 10.0:
        return None
    return score


def severity_from_token(token: str | None) -> tuple[Severity | None, float | None]:
    """Return (qualitative severity, numeric base score) for an OSV token.

    (None, None) when the token is absent, malformed, or out of range; the
    caller records the gap instead of guessing a band.
    """
    if token is None or not token.strip():
        return (None, None)
    try:
        score = _base_score(token.strip())
    except CVSSError:
        return (None, None)
    if score is None:
        return (None, None)
    return (band_for_score(score), score)
