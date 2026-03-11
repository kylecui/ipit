"""
FastAPI interface for Threat Intelligence Reasoning Engine.
"""

import logging
import os
from app.config import settings

# Configure logging BEFORE anything else imports loggers
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional
from app.service import ThreatIntelService
from app.i18n import i18n
from models import ContextProfile
from reporters.json_reporter import JSONReporter
from reporters.html_reporter import HTMLReporter
from reporters.narrative_reporter import NarrativeReporter

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Threat Intelligence Reasoning Engine",
    description="Multi-source threat intelligence analysis and reasoning engine",
    version="0.1.0",
    root_path=settings.root_path,
)

service = ThreatIntelService()
json_reporter = JSONReporter()
html_reporter = HTMLReporter()
narrative_reporter = NarrativeReporter()

templates = Jinja2Templates(
    directory=os.path.join(os.path.dirname(__file__), "..", "templates")
)


class AnalyzeRequest(BaseModel):
    """Request model for context-aware analysis."""

    ip: str
    context: Optional[ContextProfile] = None
    refresh: bool = False


def _get_lang(request: Request) -> str:
    """Resolve display language: ?lang= query param → cookie → config default."""
    lang = request.query_params.get("lang")
    if lang in i18n.SUPPORTED_LANGS:
        return lang
    cookie_lang = request.cookies.get("preferred_locale")
    if cookie_lang in i18n.SUPPORTED_LANGS:
        return cookie_lang
    return settings.language


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


@app.get("/api/v1/debug/sources/{ip}")
async def debug_sources(ip: str):
    """Debug endpoint: show raw plugin results for an IP (always refreshes).

    v2.0: Uses PluginRegistry instead of CollectorAggregator.
    """
    import asyncio
    import yaml

    try:
        from plugins import PluginRegistry

        config_path = os.path.join(
            os.path.dirname(__file__), "..", "config", "plugins.yaml"
        )
        with open(config_path, "r", encoding="utf-8") as f:
            plugin_config = yaml.safe_load(f) or {}

        registry = PluginRegistry(plugin_config)
        registry.discover()

        plugins = registry.get_enabled("ip")

        async def _safe_query(plugin, observable):
            try:
                return await plugin.query(observable, "ip")
            except Exception as e:
                from plugins import PluginResult

                return PluginResult(
                    source=plugin.metadata.name,
                    ok=False,
                    raw_data=None,
                    normalized_data=None,
                    evidence=[],
                    error=str(e),
                )

        results = await asyncio.gather(*[_safe_query(p, ip) for p in plugins])

        summary = {}
        for result in results:
            data = result.raw_data
            summary[result.source] = {
                "ok": result.ok,
                "error": result.error,
                "data_keys": list(data.keys()) if isinstance(data, dict) else None,
                "data_preview": {
                    k: v
                    for k, v in (data or {}).items()
                    if isinstance(v, (int, float, str, bool))
                }
                if isinstance(data, dict)
                else None,
            }

        return JSONResponse(content=summary)
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Debug collection failed: {str(e)}"
        )


@app.get("/")
async def dashboard(request: Request):
    """Web dashboard for IP analysis."""
    lang = _get_lang(request)
    t = i18n.get_translator(lang)
    response = templates.TemplateResponse(
        "dashboard.html.j2",
        {"request": request, "t": t, "lang": lang, "root_path": settings.root_path},
    )
    response.set_cookie("preferred_locale", lang, max_age=365 * 24 * 3600)
    return response


@app.post("/analyze")
async def analyze_web(
    request: Request, ip: str = Form(...), refresh: bool = Form(False)
):
    """Web form submission for IP analysis."""
    lang = _get_lang(request)
    t = i18n.get_translator(lang)
    try:
        verdict = await service.analyze_ip(ip, refresh=refresh)
        html_report = html_reporter.generate(verdict, lang=lang)
        response = templates.TemplateResponse(
            "dashboard.html.j2",
            {
                "request": request,
                "verdict": verdict,
                "html_report": html_report,
                "ip": ip,
                "t": t,
                "lang": lang,
                "root_path": settings.root_path,
            },
        )
    except Exception as e:
        response = templates.TemplateResponse(
            "dashboard.html.j2",
            {
                "request": request,
                "error": str(e),
                "ip": ip,
                "t": t,
                "lang": lang,
                "root_path": settings.root_path,
            },
        )
    response.set_cookie("preferred_locale", lang, max_age=365 * 24 * 3600)
    return response


@app.post("/api/v1/report/generate")
async def generate_report(request: Request, ip: str = Form(...)):
    """Generate a detailed narrative threat intelligence report."""
    lang = _get_lang(request)
    try:
        # Always refresh: reports are on-demand, and cached verdicts from
        # before the raw_sources field was added have empty raw_sources which
        # causes sections 2-5 of the narrative report to show no data.
        verdict = await service.analyze_ip(ip, refresh=True)
        html = await narrative_reporter.generate(verdict, lang=lang)
        return HTMLResponse(content=html)
    except Exception as e:
        logger.error("Report generation failed for %s: %s", ip, e)
        raise HTTPException(
            status_code=500, detail=f"Report generation failed: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
