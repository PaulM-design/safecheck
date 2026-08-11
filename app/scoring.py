from app.models import Finding

WEIGHTS = {"info": 0, "low": 5, "medium": 12, "high": 25, "critical": 40}


def calculate_score(findings: list[Finding]) -> tuple[int, str]:
    # Diminishing returns prevent many small observations from overwhelming severe issues.
    raw = sum(WEIGHTS[f.severity.value] for f in findings)
    score = min(100, raw)
    level = "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low"
    return score, level

