# SafeCheck

A lightweight FastAPI service for **authorized, non-invasive** website security posture checks. It inspects response headers, cookies, TLS certificate/protocol negotiation, common OWASP configuration issues, CMS extension versions exposed in public asset URLs, directory-listing signatures, and visible login rate-limit signals.

It does **not** brute-force credentials, exploit vulnerabilities, recursively crawl, enumerate directories, or claim that a detected version is vulnerable without an authoritative advisory comparison.

## Run

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs`, or:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/scan -Method Post -ContentType application/json -Body '{"target":"https://example.com","authorized":true,"use_llm":false}'
```

To enable the optional narrative summary, copy `.env.example` to `.env` and configure an OpenAI-compatible chat-completions endpoint. Risk scores and findings are deterministic; the LLM only rewrites the supplied findings into a short summary.

## Safety and interpretation

- Scan only systems you own or have explicit written permission to assess.
- Private, loopback, link-local, reserved, credential-bearing URLs, unusual ports, mixed DNS answers, and cross-host redirects are rejected to reduce SSRF risk.
- Each scan has a small fixed request budget and low connection concurrency.
- “No visible brute-force protection” is an observation, not proof: server-side controls may be invisible.
- Public CMS version strings are inventory clues. Confirm versions and consult vendor advisories before assigning vulnerability status.
- Run behind authentication and rate limiting before exposing this API to other users.

## Tests

```powershell
pytest
ruff check .
```
