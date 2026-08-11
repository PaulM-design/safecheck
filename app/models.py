from enum import Enum

from pydantic import BaseModel, Field, HttpUrl


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Finding(BaseModel):
    check: str
    title: str
    severity: Severity
    evidence: str
    recommendation: str
    owasp: str | None = None


class ScanRequest(BaseModel):
    target: HttpUrl
    authorized: bool = Field(
        description="Confirms the caller owns the target or has explicit permission to test it."
    )
    use_llm: bool = False


class ScanReport(BaseModel):
    target: str
    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    summary: str
    findings: list[Finding]
    requests_made: int
    llm_enhanced: bool = False
