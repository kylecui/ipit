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
from starlette.middleware.sessions import SessionMiddleware
from typing import Any, Optional
from app.service import ThreatIntelService
from app.i18n import i18n
from models import ContextProfile
from reporters.json_reporter import JSONReporter
from reporters.html_reporter import HTMLReporter
from reporters.narrative_reporter import NarrativeReporter
from admin.routes import router as admin_router
from admin.database import admin_db
from admin.auth import get_current_user, login_redirect

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Threat Intelligence Reasoning Engine",
    description="Multi-source threat intelligence analysis and reasoning engine",
    version="2.0.0",
    root_path=settings.root_path,
)

# Session middleware for admin portal cookie-based auth
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret_key)

# Admin portal routes
app.include_router(admin_router)

service = ThreatIntelService()
json_reporter = JSONReporter()
html_reporter = HTMLReporter()
narrative_reporter = NarrativeReporter()

templates = Jinja2Templates(
    directory=os.path.join(os.path.dirname(__file__), "..", "templates")
)


@app.on_event("startup")
async def startup_event():
    """Initialize admin database, ensure default admin user, wire log handler."""
    admin_db.ensure_admin_exists()

    # Attach in-memory log handler for the admin log viewer
    from admin.log_handler import MemoryLogHandler, LogStore

    store = LogStore()
    handler = MemoryLogHandler(store)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logging.getLogger().addHandler(handler)


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
async def analyze_ip(ip: str, request: Request, refresh: bool = False):
    """Analyze an IP address for threats."""
    try:
        user = get_current_user(request)
        user_id = user["id"] if user else None
        verdict = await service.analyze_ip(ip, refresh=refresh, user_id=user_id)
        report = json_reporter.generate(verdict)

        # Parse back to dict for JSON response
        import json

        return JSONResponse(content=json.loads(report))

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.post("/api/v1/analyze/ip")
async def analyze_ip_with_context(request: Request, body: AnalyzeRequest):
    """Context-aware IP analysis."""
    try:
        user = get_current_user(request)
        user_id = user["id"] if user else None
        verdict = await service.analyze_ip(
            body.ip, body.context, body.refresh, user_id=user_id
        )
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


@app.get("/api/v1/results/{ip}/history")
async def get_result_history(ip: str, request: Request, limit: int = 20):
    """Return historical query snapshots for an IP.

    Supports the timeline comparison feature — shows score changes
    across multiple queries of the same IP over time.
    """
    from storage.result_store import result_store

    try:
        snapshots = result_store.get_snapshot_history(ip, limit=limit)
        return JSONResponse(
            content={"ip": ip, "snapshots": snapshots, "count": len(snapshots)}
        )
    except Exception as e:
        logger.error("Failed to fetch history for %s: %s", ip, e)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch result history: {str(e)}",
        )


@app.get("/api/v1/results/snapshot/{snapshot_id}")
async def get_snapshot_detail(snapshot_id: int, request: Request):
    """Return a single query snapshot by ID (for side-by-side diff).

    Returns the full verdict JSON and source data for detailed comparison.
    """
    from storage.result_store import result_store

    snapshot = result_store.get_snapshot_by_id(snapshot_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail=f"Snapshot {snapshot_id} not found")
    return JSONResponse(content=snapshot)


@app.get("/api/v1/debug/sources/{ip}")
async def debug_sources(ip: str):
    """Debug endpoint: show raw plugin results for an IP (always refreshes).

    v2.0: Uses PluginRegistry instead of CollectorAggregator.
    """
    import asyncio
    import yaml

    try:
        from plugins import PluginRegistry, PluginResult, SandboxedPluginRunner

        config_path = os.path.join(
            os.path.dirname(__file__), "..", "config", "plugins.yaml"
        )
        with open(config_path, "r", encoding="utf-8") as f:
            plugin_config = yaml.safe_load(f) or {}

        registry = PluginRegistry(plugin_config)
        registry.discover()
        sandbox_runner = SandboxedPluginRunner()

        plugins = registry.get_enabled("ip")

        async def _safe_query(plugin, observable):
            try:
                if registry.is_sandboxed(plugin.metadata.name):
                    sandbox_config = registry.get_sandbox_config(plugin.metadata.name)
                    return await sandbox_runner.run(
                        plugin, observable, "ip", sandbox_config
                    )
                return await plugin.query(observable, "ip")
            except Exception as e:
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
    user = get_current_user(request)
    if not user:
        return login_redirect(request)
    lang = _get_lang(request)
    t = i18n.get_translator(lang)
    response = templates.TemplateResponse(
        "dashboard.html.j2",
        {
            "request": request,
            "t": t,
            "lang": lang,
            "root_path": settings.root_path,
            "user": user,
        },
    )
    response.set_cookie("preferred_locale", lang, max_age=365 * 24 * 3600)
    return response


@app.post("/analyze")
async def analyze_web(
    request: Request, ip: str = Form(...), refresh: bool = Form(False)
):
    """Web form submission for IP analysis."""
    user = get_current_user(request)
    if not user:
        return login_redirect(request)
    lang = _get_lang(request)
    t = i18n.get_translator(lang)
    try:
        verdict = await service.analyze_ip(ip, refresh=refresh, user_id=user["id"])
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
                "user": user,
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
                "user": user,
            },
        )
    response.set_cookie("preferred_locale", lang, max_age=365 * 24 * 3600)
    return response


@app.post("/api/v1/report/generate")
async def generate_report(
    request: Request,
    ip: str = Form(...),
    regenerate: bool = Form(False),
):
    """Generate a detailed narrative threat intelligence report.

    V2 principle: Report generation NEVER triggers new data queries.
    All data must be collected during the analysis phase first.

    If no cached/persisted analysis exists for the IP, returns 404
    with instructions to run analysis first.

    Args:
        ip: The IP address to generate a report for.
        regenerate: If True, bypass cached report and invoke LLM again.
    """
    user = get_current_user(request)
    if not user:
        return login_redirect(request)
    lang = _get_lang(request)

    try:
        # Step 1: Try to get existing verdict from cache ONLY — never query.
        cached_verdict = service.query_engine.cache.get_verdict(ip)
        if cached_verdict is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"No analysis data found for {ip}. "
                    "Please run an analysis first before generating a report."
                ),
            )

        # Step 2: Check for a cached report (unless regenerate is requested)
        if not regenerate:
            from storage.result_store import result_store

            cached_report = result_store.get_latest_report(
                ip=ip, user_id=user["id"], lang=lang
            )
            if cached_report:
                logger.info(
                    "Serving cached report for %s (user=%s, lang=%s)",
                    ip,
                    user["id"],
                    lang,
                )
                return HTMLResponse(content=cached_report["report_html"])

        # Step 3: Generate new report from existing verdict (no new queries)
        #   If regenerating, archive old reports first (preserves history for comparison)
        if regenerate:
            from storage.result_store import result_store as _rs

            archived = _rs.archive_reports(ip=ip, user_id=user["id"])
            if archived:
                logger.info(
                    "Archived %d previous report(s) for %s (user=%s)",
                    archived,
                    ip,
                    user["id"],
                )

        llm_settings = admin_db.get_llm_settings(user["id"])

        # Resolve query_date from the latest snapshot for staleness detection
        from storage.result_store import result_store as _store
        from datetime import datetime

        query_date = None
        latest_snapshot = _store.get_latest_snapshot(ip=ip)
        if latest_snapshot and latest_snapshot.get("queried_at"):
            try:
                query_date = datetime.fromisoformat(latest_snapshot["queried_at"])
            except (ValueError, TypeError):
                pass

        html = await narrative_reporter.generate(
            cached_verdict,
            lang=lang,
            llm_overrides=llm_settings,
            query_date=query_date,
        )

        # Step 4: Persist the generated report
        from storage.result_store import result_store

        result_store.save_report(
            ip=ip,
            user_id=user["id"],
            report_html=html,
            llm_enhanced=llm_settings.get("api_key", "") != "",
            lang=lang,
        )

        return HTMLResponse(content=html)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Report generation failed for %s: %s", ip, e)
        raise HTTPException(
            status_code=500, detail=f"Report generation failed: {str(e)}"
        )


@app.get("/api/v1/reports/{ip}/history")
async def get_report_history(ip: str, request: Request, limit: int = 20):
    """Return historical reports for an IP (per-user).

    Supports report comparison — shows how reports evolved over time.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse(
            status_code=401, content={"detail": "Authentication required"}
        )

    from storage.result_store import result_store

    try:
        reports = result_store.get_report_history(
            ip=ip, user_id=user["id"], limit=limit
        )
        return JSONResponse(
            content={"ip": ip, "reports": reports, "count": len(reports)}
        )
    except Exception as e:
        logger.error("Failed to fetch report history for %s: %s", ip, e)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch report history: {str(e)}",
        )


@app.get("/api/v1/results/{ip}/compare")
async def compare_snapshots(
    ip: str,
    request: Request,
    snapshot_a: int | None = None,
    snapshot_b: int | None = None,
):
    """Compare two query snapshots for an IP.

    If snapshot_a and snapshot_b are provided, performs a detailed
    side-by-side diff. Otherwise returns timeline data (score history
    across all snapshots).

    Returns:
        - Timeline mode (no params): list of {queried_at, final_score, level}
        - Diff mode (a & b): detailed field-by-field comparison
    """
    from storage.result_store import result_store
    import json as _json

    try:
        if snapshot_a is not None and snapshot_b is not None:
            # Side-by-side diff mode
            snap_a = result_store.get_snapshot_by_id(snapshot_a)
            snap_b = result_store.get_snapshot_by_id(snapshot_b)
            if not snap_a:
                raise HTTPException(
                    status_code=404, detail=f"Snapshot {snapshot_a} not found"
                )
            if not snap_b:
                raise HTTPException(
                    status_code=404, detail=f"Snapshot {snapshot_b} not found"
                )

            # Compute diff
            diff = _compute_snapshot_diff(snap_a, snap_b)
            return JSONResponse(
                content={
                    "mode": "diff",
                    "ip": ip,
                    "snapshot_a": {
                        "id": snap_a["id"],
                        "queried_at": snap_a["queried_at"],
                        "final_score": snap_a["final_score"],
                        "level": snap_a["level"],
                    },
                    "snapshot_b": {
                        "id": snap_b["id"],
                        "queried_at": snap_b["queried_at"],
                        "final_score": snap_b["final_score"],
                        "level": snap_b["level"],
                    },
                    "diff": diff,
                }
            )
        else:
            # Timeline mode — return score history
            snapshots = result_store.get_snapshot_history(ip, limit=50)
            timeline = [
                {
                    "id": s["id"],
                    "queried_at": s["queried_at"],
                    "final_score": s["final_score"],
                    "level": s["level"],
                    "is_archived": s.get("is_archived", 0),
                }
                for s in reversed(snapshots)  # oldest first for timeline
            ]
            return JSONResponse(
                content={
                    "mode": "timeline",
                    "ip": ip,
                    "timeline": timeline,
                    "count": len(timeline),
                }
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Comparison failed for %s: %s", ip, e)
        raise HTTPException(status_code=500, detail=f"Comparison failed: {str(e)}")


def _compute_snapshot_diff(
    snap_a: dict[str, Any], snap_b: dict[str, Any]
) -> dict[str, Any]:
    """Compute a structured diff between two query snapshots.

    Compares:
      - Score changes (final_score, level)
      - Evidence items (added, removed, changed)
      - Source data differences
    """
    import json as _json

    diff: dict[str, Any] = {
        "score_change": snap_b["final_score"] - snap_a["final_score"],
        "level_change": {
            "from": snap_a["level"],
            "to": snap_b["level"],
            "changed": snap_a["level"] != snap_b["level"],
        },
        "time_delta": {
            "from": snap_a["queried_at"],
            "to": snap_b["queried_at"],
        },
        "evidence_diff": {"added": [], "removed": [], "changed": []},
        "source_diff": {},
    }

    # Parse verdict JSON for evidence comparison
    try:
        verdict_a = _json.loads(snap_a.get("verdict_json", "{}"))
        verdict_b = _json.loads(snap_b.get("verdict_json", "{}"))
    except (TypeError, _json.JSONDecodeError):
        verdict_a = {}
        verdict_b = {}

    # Compare evidence items by source+title key
    evidence_a = {
        f"{e.get('source', '')}::{e.get('title', '')}": e
        for e in verdict_a.get("evidence", [])
    }
    evidence_b = {
        f"{e.get('source', '')}::{e.get('title', '')}": e
        for e in verdict_b.get("evidence", [])
    }

    # Added evidence (in B but not A)
    for key in set(evidence_b) - set(evidence_a):
        diff["evidence_diff"]["added"].append(evidence_b[key])

    # Removed evidence (in A but not B)
    for key in set(evidence_a) - set(evidence_b):
        diff["evidence_diff"]["removed"].append(evidence_a[key])

    # Changed evidence (same key, different score_delta)
    for key in set(evidence_a) & set(evidence_b):
        ea = evidence_a[key]
        eb = evidence_b[key]
        if ea.get("score_delta") != eb.get("score_delta") or ea.get(
            "severity"
        ) != eb.get("severity"):
            diff["evidence_diff"]["changed"].append(
                {
                    "key": key,
                    "from": ea,
                    "to": eb,
                }
            )

    # Compare source data
    try:
        sources_a = _json.loads(snap_a.get("sources_json", "{}") or "{}")
        sources_b = _json.loads(snap_b.get("sources_json", "{}") or "{}")
    except (TypeError, _json.JSONDecodeError):
        sources_a = {}
        sources_b = {}

    all_sources = set(list(sources_a.keys()) + list(sources_b.keys()))
    for source in all_sources:
        sa = sources_a.get(source)
        sb = sources_b.get(source)
        if sa is None and sb is not None:
            diff["source_diff"][source] = {"status": "added"}
        elif sa is not None and sb is None:
            diff["source_diff"][source] = {"status": "removed"}
        elif sa != sb:
            diff["source_diff"][source] = {"status": "changed"}
        # else: unchanged — don't include

    return diff


@app.get("/compare", response_class=HTMLResponse)
async def comparison_page(request: Request, ip: str = ""):
    """Comparison page for viewing score timeline and side-by-side diffs."""
    user = get_current_user(request)
    if not user:
        return login_redirect(request)
    lang = _get_lang(request)
    t = i18n.get_translator(lang)
    return templates.TemplateResponse(
        "comparison.html.j2",
        {
            "request": request,
            "t": t,
            "lang": lang,
            "root_path": settings.root_path,
            "user": user,
            "ip": ip,
        },
    )


@app.get("/api/v1/reports/detail/{report_id}")
async def get_report_detail(report_id: int, request: Request):
    """Return a single stored report by ID (for side-by-side comparison)."""
    user = get_current_user(request)
    if not user:
        return JSONResponse(
            status_code=401, content={"detail": "Authentication required"}
        )

    from storage.result_store import result_store

    report = result_store.get_report_by_id(report_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")

    # Per-user isolation: only allow users to see their own reports
    if report["user_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")

    return JSONResponse(content=report)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
