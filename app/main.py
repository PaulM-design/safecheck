from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.llm import enhance_report
from app.models import ScanReport, ScanRequest
from app.safety import UnsafeTarget
from app.scanner import Scanner
from app.scoring import calculate_score

STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(title="SafeCheck", version="0.1.0")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
async def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanReport)
async def scan(request: ScanRequest) -> ScanReport:
    if not request.authorized:
        raise HTTPException(403, "You must confirm ownership or explicit authorization")
    try:
        scanner = Scanner()
        findings, count = await scanner.scan(str(request.target))
    except UnsafeTarget as exc:
        raise HTTPException(400, str(exc)) from exc
    except (httpx.HTTPError, RuntimeError) as exc:
        raise HTTPException(502, f"Target scan failed: {type(exc).__name__}") from exc

    score, level = calculate_score(findings)
    summary = f"Found {len(findings)} observations. Deterministic risk rating: {level} ({score}/100)."
    enhanced = False
    if request.use_llm:
        try:
            generated = await enhance_report(str(request.target), score, findings)
            if generated:
                summary, enhanced = generated, True
        except (httpx.HTTPError, KeyError, IndexError, TypeError):
            pass  # The deterministic report remains available if the optional LLM fails.
    return ScanReport(target=str(request.target), risk_score=score, risk_level=level,
                      summary=summary, findings=findings, requests_made=count,
                      llm_enhanced=enhanced)
