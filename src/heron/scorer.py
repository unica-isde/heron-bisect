"""Combine the indicator points into a score and a verdict."""

from heron.features import ALL_CHECKS
from heron.models import ParsedEmail, TriageResult, Verdict

PHISHING_THRESHOLD = 5
SUSPICIOUS_THRESHOLD = 3


def triage(email: ParsedEmail) -> TriageResult:
    """Run every check on one message and decide its verdict."""
    score = sum(check(email) for check in ALL_CHECKS)
    return TriageResult(email.email_id, score, verdict_for(score))


def verdict_for(score: int) -> Verdict:
    """Map a score to a verdict."""
    if score >= PHISHING_THRESHOLD:
        return Verdict.PHISHING
    if score >= SUSPICIOUS_THRESHOLD:
        return Verdict.SUSPICIOUS
    return Verdict.BENIGN
