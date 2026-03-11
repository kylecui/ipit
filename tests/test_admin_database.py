"""
Unit tests for admin database bootstrap behavior.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from admin.database import AdminDB


@pytest.fixture
def temp_db_path(tmp_path: Path) -> Path:
    return tmp_path / "admin-test.db"


def test_ensure_admin_exists_creates_default_admin_once(
    temp_db_path: Path, monkeypatch
):
    """Bootstrap creates exactly one admin user on an empty database."""
    monkeypatch.setenv("ADMIN_PASSWORD", "secret123")
    db = AdminDB(str(temp_db_path))

    db.ensure_admin_exists()

    users = db.list_users()
    assert len(users) == 1
    assert users[0]["username"] == "admin"
    assert users[0]["is_admin"] == 1
    assert db.verify_password("admin", "secret123") is not None


def test_ensure_admin_exists_is_idempotent(temp_db_path: Path, monkeypatch):
    """Repeated bootstrap calls do not create duplicate admin users."""
    monkeypatch.setenv("ADMIN_PASSWORD", "secret123")
    db = AdminDB(str(temp_db_path))

    db.ensure_admin_exists()
    db.ensure_admin_exists()
    db.ensure_admin_exists()

    users = db.list_users()
    assert len(users) == 1
    assert users[0]["username"] == "admin"


def test_ensure_admin_exists_does_not_override_existing_user_db(
    temp_db_path: Path, monkeypatch
):
    """Bootstrap is a no-op when persisted user data already exists."""
    monkeypatch.setenv("ADMIN_PASSWORD", "secret123")
    db = AdminDB(str(temp_db_path))
    user_id = db.create_user("alice", "pw", display_name="Alice", is_admin=False)

    db.ensure_admin_exists()

    users = db.list_users()
    assert len(users) == 1
    assert users[0]["id"] == user_id
    assert users[0]["username"] == "alice"
    assert db.get_user_by_username("admin") is None
