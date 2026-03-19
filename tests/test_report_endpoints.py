"""Endpoint-level regression tests for report and history flows."""

from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient

from app import api as api_module
from app.api import app


def _user() -> dict[str, object]:
    return {"id": 3, "is_admin": False, "username": "jzzn", "display_name": "jzzn"}


def test_result_history_returns_visible_snapshots(monkeypatch) -> None:
    """History endpoint should return visible snapshots for the current user."""
    monkeypatch.setattr(api_module, "get_current_user", lambda request: _user())

    fake_store = SimpleNamespace(
        get_visible_snapshot_history=lambda ip,
        user_id=None,
        is_admin=False,
        limit=20: [
            {
                "id": 14,
                "ip": ip,
                "final_score": 45,
                "level": "Medium",
                "queried_at": "2026-03-18T06:42:23+00:00",
                "api_key_type": "personal",
                "user_id": user_id,
            }
        ]
    )
    monkeypatch.setattr("storage.result_store.result_store", fake_store)

    client = TestClient(app)
    response = client.get("/api/v1/results/150.107.38.251/history")

    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 1
    assert payload["snapshots"][0]["id"] == 14


def test_snapshot_detail_enforces_access_control(monkeypatch) -> None:
    """Snapshot detail endpoint should reject snapshots owned by another user."""
    monkeypatch.setattr(api_module, "get_current_user", lambda request: _user())

    fake_store = SimpleNamespace(
        get_snapshot_by_id=lambda snapshot_id: {
            "id": snapshot_id,
            "ip": "150.107.38.251",
            "api_key_type": "personal",
            "user_id": 999,
        }
    )
    monkeypatch.setattr("storage.result_store.result_store", fake_store)

    client = TestClient(app)
    response = client.get("/api/v1/results/snapshot/55")

    assert response.status_code == 403
    assert response.json()["detail"] == "Access denied"


def test_report_detail_returns_owned_report(monkeypatch) -> None:
    """Report detail endpoint should return the owned stored report payload."""
    monkeypatch.setattr(api_module, "get_current_user", lambda request: _user())

    fake_store = SimpleNamespace(
        get_report_by_id=lambda report_id: {
            "id": report_id,
            "ip": "150.107.38.251",
            "user_id": 3,
            "report_html": "<html>owned report</html>",
        }
    )
    monkeypatch.setattr("storage.result_store.result_store", fake_store)

    client = TestClient(app)
    response = client.get("/api/v1/reports/detail/9")

    assert response.status_code == 200
    assert response.json()["id"] == 9
    assert response.json()["report_html"] == "<html>owned report</html>"


def test_compare_reports_page_rejects_cross_ip_comparison(monkeypatch) -> None:
    """Compare page should reject comparing reports from different IPs."""
    monkeypatch.setattr(api_module, "get_current_user", lambda request: _user())

    reports = {
        1: {"id": 1, "ip": "1.1.1.1", "user_id": 3, "report_html": "a"},
        2: {"id": 2, "ip": "2.2.2.2", "user_id": 3, "report_html": "b"},
    }
    fake_store = SimpleNamespace(
        get_report_by_id=lambda report_id: reports.get(report_id),
        get_report_history=lambda ip, user_id, limit=20: [],
    )
    monkeypatch.setattr("storage.result_store.result_store", fake_store)

    client = TestClient(app)
    response = client.get("/reports/compare?report_a=1&report_b=2")

    assert response.status_code == 400
    assert response.json()["detail"] == "Compared reports must belong to the same IP"


def test_compare_snapshots_timeline_returns_oldest_first(monkeypatch) -> None:
    """Compare API timeline mode should return oldest-first visible snapshots."""
    monkeypatch.setattr(api_module, "get_current_user", lambda request: _user())

    fake_store = SimpleNamespace(
        get_visible_snapshot_history=lambda ip,
        user_id=None,
        is_admin=False,
        limit=50: [
            {
                "id": 12,
                "queried_at": "2026-03-18T06:42:23+00:00",
                "final_score": 50,
                "level": "High",
                "is_archived": 0,
            },
            {
                "id": 11,
                "queried_at": "2026-03-17T06:42:23+00:00",
                "final_score": 30,
                "level": "Medium",
                "is_archived": 1,
            },
        ]
    )
    monkeypatch.setattr("storage.result_store.result_store", fake_store)

    client = TestClient(app)
    response = client.get("/api/v1/results/150.107.38.251/compare")

    assert response.status_code == 200
    payload = response.json()
    assert payload["mode"] == "timeline"
    assert payload["timeline"][0]["id"] == 11
    assert payload["timeline"][1]["id"] == 12


def test_compare_snapshots_diff_returns_structured_diff(monkeypatch) -> None:
    """Compare API diff mode should return structured evidence/source changes."""
    monkeypatch.setattr(api_module, "get_current_user", lambda request: _user())

    snapshots = {
        11: {
            "id": 11,
            "queried_at": "2026-03-17T06:42:23+00:00",
            "final_score": 20,
            "level": "Low",
            "api_key_type": "personal",
            "user_id": 3,
            "verdict_json": '{"evidence":[{"source":"rdap","title":"Owner","severity":"low","score_delta":5}]}',
            "sources_json": '{"rdap":{"ok":true}}',
        },
        12: {
            "id": 12,
            "queried_at": "2026-03-18T06:42:23+00:00",
            "final_score": 55,
            "level": "High",
            "api_key_type": "personal",
            "user_id": 3,
            "verdict_json": '{"evidence":[{"source":"rdap","title":"Owner","severity":"medium","score_delta":10},{"source":"vt","title":"Detections","severity":"high","score_delta":20}]}',
            "sources_json": '{"rdap":{"ok":true},"virustotal":{"ok":true}}',
        },
    }
    fake_store = SimpleNamespace(
        get_snapshot_by_id=lambda snapshot_id: snapshots.get(snapshot_id)
    )
    monkeypatch.setattr("storage.result_store.result_store", fake_store)

    client = TestClient(app)
    response = client.get(
        "/api/v1/results/150.107.38.251/compare?snapshot_a=11&snapshot_b=12"
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["mode"] == "diff"
    assert payload["diff"]["score_change"] == 35
    assert payload["diff"]["level_change"]["changed"] is True
    assert payload["diff"]["evidence_diff"]["added"][0]["source"] == "vt"
    assert payload["diff"]["evidence_diff"]["changed"][0]["key"] == "rdap::Owner"
    assert payload["diff"]["source_diff"]["virustotal"]["status"] == "added"


def test_report_history_requires_authentication(monkeypatch) -> None:
    """Report history API should enforce authentication."""
    monkeypatch.setattr(api_module, "get_current_user", lambda request: None)

    client = TestClient(app)
    response = client.get("/api/v1/reports/150.107.38.251/history")

    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"
