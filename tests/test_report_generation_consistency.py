"""Regression tests for report generation consistency between cache and snapshots."""

from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient

from app import api as api_module
from app.api import app
from models import Verdict


def _make_verdict(org: str) -> Verdict:
    return Verdict(
        object_type="ip",
        object_value="150.107.38.251",
        reputation_score=10,
        contextual_score=0,
        final_score=10,
        level="Low",
        confidence=0.5,
        decision="allow_with_monitoring",
        summary=f"Ownership: {org}",
        evidence=[],
        tags=[],
        raw_sources={
            "rdap": {
                "ok": True,
                "data": {
                    "name": org,
                    "country": "HK",
                    "network": "150.107.36.0/22",
                },
            }
        },
    )


def test_generate_report_prefers_latest_snapshot_verdict_over_cache(
    monkeypatch,
) -> None:
    """Report generation should use the latest persisted snapshot verdict over stale cache."""
    cache_verdict = _make_verdict("STALE-CACHE-ORG")
    snapshot_verdict = _make_verdict("SNAPSHOT-ORG")
    saved_reports: list[dict[str, object]] = []

    monkeypatch.setattr(
        api_module,
        "get_current_user",
        lambda request: {"id": 3, "is_admin": False, "username": "jzzn"},
    )
    monkeypatch.setattr(
        api_module.service.query_engine.cache,
        "get_verdict",
        lambda ip: cache_verdict,
    )

    fake_result_store = SimpleNamespace(
        get_latest_snapshot=lambda ip,
        user_id=None,
        api_key_type="shared",
        staleness_days=7: {
            "id": 99,
            "queried_at": "2026-03-18T05:00:00+00:00",
            "verdict_json": snapshot_verdict.model_dump_json(),
        }
        if api_key_type == "personal"
        else None,
        get_latest_report=lambda **kwargs: None,
        save_report=lambda **kwargs: saved_reports.append(kwargs) or 123,
        archive_reports=lambda **kwargs: 0,
    )

    monkeypatch.setattr("storage.result_store.result_store", fake_result_store)
    monkeypatch.setattr(
        api_module.admin_db,
        "resolve_effective_llm_access",
        lambda user_id: {"fingerprint": "", "source": "template", "model": ""},
    )

    captured = {}

    async def _fake_generate(verdict, lang="en", llm_overrides=None, query_date=None):
        captured["verdict"] = verdict
        captured["query_date"] = query_date.isoformat() if query_date else None
        return (
            f"<html>{verdict.raw_sources['rdap']['data']['name']}</html>",
            False,
            False,
        )

    monkeypatch.setattr(api_module.narrative_reporter, "generate", _fake_generate)

    client = TestClient(app)
    response = client.post(
        "/api/v1/report/generate?lang=en",
        data={"ip": "150.107.38.251", "regenerate": "true"},
    )

    assert response.status_code == 200
    assert "SNAPSHOT-ORG" in response.text
    assert captured["verdict"].raw_sources["rdap"]["data"]["name"] == "SNAPSHOT-ORG"
    assert captured["query_date"] == "2026-03-18T05:00:00+00:00"
    assert saved_reports[0]["snapshot_id"] == 99


def test_generate_report_loads_snapshot_when_cache_is_missing(monkeypatch) -> None:
    """Report generation should succeed from persisted snapshot data on cache miss."""
    snapshot_verdict = _make_verdict("SNAPSHOT-ONLY-ORG")

    monkeypatch.setattr(
        api_module,
        "get_current_user",
        lambda request: {"id": 3, "is_admin": False, "username": "jzzn"},
    )
    monkeypatch.setattr(
        api_module.service.query_engine.cache,
        "get_verdict",
        lambda ip: None,
    )

    fake_result_store = SimpleNamespace(
        get_latest_snapshot=lambda ip,
        user_id=None,
        api_key_type="shared",
        staleness_days=7: {
            "id": 100,
            "queried_at": "2026-03-18T06:00:00+00:00",
            "verdict_json": snapshot_verdict.model_dump_json(),
        }
        if api_key_type == "personal"
        else None,
        get_latest_report=lambda **kwargs: None,
        save_report=lambda **kwargs: 124,
        archive_reports=lambda **kwargs: 0,
    )

    monkeypatch.setattr("storage.result_store.result_store", fake_result_store)
    monkeypatch.setattr(
        api_module.admin_db,
        "resolve_effective_llm_access",
        lambda user_id: {"fingerprint": "", "source": "template", "model": ""},
    )

    async def _fake_generate(verdict, lang="en", llm_overrides=None, query_date=None):
        return (
            f"<html>{verdict.raw_sources['rdap']['data']['name']}</html>",
            False,
            False,
        )

    monkeypatch.setattr(api_module.narrative_reporter, "generate", _fake_generate)

    client = TestClient(app)
    response = client.post(
        "/api/v1/report/generate?lang=en",
        data={"ip": "150.107.38.251", "regenerate": "true"},
    )

    assert response.status_code == 200
    assert "SNAPSHOT-ONLY-ORG" in response.text


def test_generate_report_persists_newest_visible_snapshot_id(monkeypatch) -> None:
    """Saved reports should link to the same newest visible snapshot used for rendering."""
    shared_snapshot_verdict = _make_verdict("NEWEST-SHARED-ORG")
    personal_snapshot_verdict = _make_verdict("OLDER-PERSONAL-ORG")
    saved_reports: list[dict[str, object]] = []

    monkeypatch.setattr(
        api_module,
        "get_current_user",
        lambda request: {"id": 3, "is_admin": False, "username": "jzzn"},
    )
    monkeypatch.setattr(
        api_module.service.query_engine.cache,
        "get_verdict",
        lambda ip: _make_verdict("STALE-CACHE-ORG"),
    )

    def _fake_get_latest_snapshot(
        ip, user_id=None, api_key_type="shared", staleness_days=7
    ):
        if api_key_type == "personal":
            return {
                "id": 201,
                "queried_at": "2026-03-18T05:00:00+00:00",
                "verdict_json": personal_snapshot_verdict.model_dump_json(),
            }
        return {
            "id": 202,
            "queried_at": "2026-03-18T06:00:00+00:00",
            "verdict_json": shared_snapshot_verdict.model_dump_json(),
        }

    fake_result_store = SimpleNamespace(
        get_latest_snapshot=_fake_get_latest_snapshot,
        get_latest_report=lambda **kwargs: None,
        save_report=lambda **kwargs: saved_reports.append(kwargs) or 125,
        archive_reports=lambda **kwargs: 0,
    )

    monkeypatch.setattr("storage.result_store.result_store", fake_result_store)
    monkeypatch.setattr(
        api_module.admin_db,
        "resolve_effective_llm_access",
        lambda user_id: {"fingerprint": "", "source": "template", "model": ""},
    )

    captured = {}

    async def _fake_generate(verdict, lang="en", llm_overrides=None, query_date=None):
        captured["verdict"] = verdict
        return (
            f"<html>{verdict.raw_sources['rdap']['data']['name']}</html>",
            False,
            False,
        )

    monkeypatch.setattr(api_module.narrative_reporter, "generate", _fake_generate)

    client = TestClient(app)
    response = client.post(
        "/api/v1/report/generate?lang=en",
        data={"ip": "150.107.38.251", "regenerate": "true"},
    )

    assert response.status_code == 200
    assert "NEWEST-SHARED-ORG" in response.text
    assert (
        captured["verdict"].raw_sources["rdap"]["data"]["name"] == "NEWEST-SHARED-ORG"
    )
    assert saved_reports[0]["snapshot_id"] == 202


def test_generate_report_serves_cached_html_without_regeneration(monkeypatch) -> None:
    """Cached report HTML should be served directly when regenerate is false."""
    snapshot_verdict = _make_verdict("SNAPSHOT-ORG")

    monkeypatch.setattr(
        api_module,
        "get_current_user",
        lambda request: {"id": 3, "is_admin": False, "username": "jzzn"},
    )

    fake_result_store = SimpleNamespace(
        get_latest_snapshot=lambda ip,
        user_id=None,
        api_key_type="shared",
        staleness_days=7: {
            "id": 301,
            "queried_at": "2026-03-18T07:00:00+00:00",
            "verdict_json": snapshot_verdict.model_dump_json(),
        }
        if api_key_type == "personal"
        else None,
        get_latest_report=lambda **kwargs: {
            "report_html": "<html>cached-report</html>"
        },
    )
    monkeypatch.setattr("storage.result_store.result_store", fake_result_store)
    monkeypatch.setattr(
        api_module.admin_db,
        "resolve_effective_llm_access",
        lambda user_id: {"fingerprint": "fp", "source": "template", "model": ""},
    )

    async def _unexpected_generate(*args, **kwargs):
        raise AssertionError("narrative_reporter.generate should not be called")

    monkeypatch.setattr(api_module.narrative_reporter, "generate", _unexpected_generate)

    client = TestClient(app)
    response = client.post(
        "/api/v1/report/generate?lang=en",
        data={"ip": "150.107.38.251", "regenerate": "false"},
    )

    assert response.status_code == 200
    assert response.text == "<html>cached-report</html>"


def test_generate_report_returns_404_when_no_snapshot_or_cache_exists(
    monkeypatch,
) -> None:
    """Report generation should fail clearly when no analysis data exists."""
    monkeypatch.setattr(
        api_module,
        "get_current_user",
        lambda request: {"id": 3, "is_admin": False, "username": "jzzn"},
    )
    monkeypatch.setattr(
        api_module.service.query_engine.cache, "get_verdict", lambda ip: None
    )

    fake_result_store = SimpleNamespace(
        get_latest_snapshot=lambda ip,
        user_id=None,
        api_key_type="shared",
        staleness_days=7: None,
    )
    monkeypatch.setattr("storage.result_store.result_store", fake_result_store)

    client = TestClient(app)
    response = client.post(
        "/api/v1/report/generate?lang=en",
        data={"ip": "203.0.113.10", "regenerate": "false"},
    )

    assert response.status_code == 404
    assert "No analysis data found for 203.0.113.10" in response.json()["detail"]
