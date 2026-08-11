import json

import httpx

from app.config import settings
from app.models import Finding


async def enhance_report(target: str, score: int, findings: list[Finding]) -> str | None:
    if not settings.llm_api_key:
        return None
    facts = [
        {"title": f.title, "severity": f.severity.value, "evidence": f.evidence,
         "recommendation": f.recommendation, "owasp": f.owasp}
        for f in findings
    ]
    prompt = (
        "Write a concise, factual security executive summary (maximum 180 words). "
        "Do not invent vulnerabilities, exploitation steps, CVEs, or facts. Prioritize fixes. "
        f"Target: {target}\nDeterministic risk score: {score}/100\n"
        f"Findings JSON: {json.dumps(facts)}"
    )
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post(
            f"{settings.llm_base_url.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {settings.llm_api_key}"},
            json={"model": settings.llm_model, "temperature": 0.1, "max_tokens": 260,
                  "messages": [{"role": "user", "content": prompt}]},
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"].strip()
