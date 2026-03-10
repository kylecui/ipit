"""
FastAPI interface for Threat Intelligence Reasoning Engine.
"""

from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional
from app.service import ThreatIntelService
from models import ContextProfile
from reporters.json_reporter import JSONReporter
from reporters.html_reporter import HTMLReporter

app = FastAPI(
    title="Threat Intelligence Reasoning Engine",
    description="Multi-source threat intelligence analysis and reasoning engine",
    version="0.1.0",
)

service = ThreatIntelService()
json_reporter = JSONReporter()
html_reporter = HTMLReporter()
import os

templates = Jinja2Templates(
    directory=os.path.join(os.path.dirname(__file__), "..", "templates")
)


class AnalyzeRequest(BaseModel):
    """Request model for context-aware analysis."""

    ip: str
    context: Optional[ContextProfile] = None
    refresh: bool = False


@app.get("/healthz")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "threat-intel-reasoning-engine"}


@app.get("/readyz")
async def readiness_check():
    """Readiness check endpoint."""
    return {"status": "ready", "service": "threat-intel-reasoning-engine"}


@app.get("/api/v1/ip/{ip}")
async def analyze_ip(ip: str, refresh: bool = False):
    """Analyze an IP address for threats."""
    try:
        verdict = await service.analyze_ip(ip, refresh=refresh)
        report = json_reporter.generate(verdict)

        # Parse back to dict for JSON response
        import json

        return JSONResponse(content=json.loads(report))

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.post("/api/v1/analyze/ip")
async def analyze_ip_with_context(request: AnalyzeRequest):
    """Context-aware IP analysis."""
    try:
        verdict = await service.analyze_ip(request.ip, request.context, request.refresh)
        report = json_reporter.generate(verdict)

        # Parse back to dict for JSON response
        import json

        return JSONResponse(content=json.loads(report))

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.get("/api/v1/docs")
async def api_docs():
    """Redirect to FastAPI docs."""
    # FastAPI automatically provides /docs endpoint
    pass


@app.get("/")
async def dashboard(request: Request):
    """Web dashboard for IP analysis."""
    return templates.TemplateResponse("dashboard.html.j2", {"request": request})


@app.post("/analyze")
async def analyze_web(
    request: Request, ip: str = Form(...), refresh: bool = Form(False)
):
    """Web form submission for IP analysis."""
    try:
        verdict = await service.analyze_ip(ip, refresh=refresh)
        html_report = html_reporter.generate(verdict)
        return templates.TemplateResponse(
            "dashboard.html.j2",
            {
                "request": request,
                "verdict": verdict,
                "html_report": html_report,
                "ip": ip,
            },
        )
    except Exception as e:
        return templates.TemplateResponse(
            "dashboard.html.j2", {"request": request, "error": str(e), "ip": ip}
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
