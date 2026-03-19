"""Regression tests for login redirects under mounted root paths."""

from __future__ import annotations

from fastapi.testclient import TestClient

from admin import routes as admin_routes
from app.api import app


def test_login_submit_preserves_root_path_in_next_url(monkeypatch) -> None:
    """Posting login with an internal next URL should stay under /v2."""
    monkeypatch.setattr(admin_routes.settings, "root_path", "/v2")
    monkeypatch.setattr(
        admin_routes.admin_db,
        "verify_password",
        lambda username, password: {"id": 3, "username": username, "is_active": True},
    )
    monkeypatch.setattr(
        admin_routes.admin_db, "log_action", lambda *args, **kwargs: None
    )

    client = TestClient(app)
    response = client.post(
        "/admin/login",
        data={"username": "jzzn", "password": "jzzn1234", "next_url": "/"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/v2/"
