import pytest

from app.models import Finding, Severity
from app.safety import UnsafeTarget, validate_public_url
from app.scoring import calculate_score


@pytest.mark.asyncio
@pytest.mark.parametrize("url", ["http://127.0.0.1", "http://10.0.0.1", "http://169.254.169.254", "ftp://example.com"])
async def test_unsafe_targets_are_blocked(url):
    with pytest.raises(UnsafeTarget):
        await validate_public_url(url)


def test_scoring_is_bounded():
    findings = [Finding(check="x", title="x", severity=Severity.critical,
                        evidence="x", recommendation="x") for _ in range(4)]
    assert calculate_score(findings) == (100, "critical")
