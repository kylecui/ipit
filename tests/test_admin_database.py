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


def test_shared_llm_allowlist_user_override_and_resolver(
    temp_db_path: Path, monkeypatch
):
    """User allowlist overrides legacy assignment-derived shared access."""
    monkeypatch.setenv("ADMIN_PASSWORD", "secret123")
    db = AdminDB(str(temp_db_path))
    user_id = db.create_user("alice", "pw", display_name="Alice", is_admin=False)
    db.save_shared_llm_config(
        name="Shared One",
        api_key="shared-key",
        model="gpt-test",
        base_url="https://api.example.com/v1",
    )
    config_id = db.list_shared_llm_configs()[0]["id"]
    db.assign_shared_llm_to_user(user_id, config_id)

    legacy = db.resolve_effective_llm_access(user_id)
    assert legacy["source"] == "shared-user"

    db.set_user_llm_allowlist(user_id, config_id, False)
    denied = db.resolve_effective_llm_access(user_id)
    assert denied["source"] != "shared-user"

    db.set_user_llm_allowlist(user_id, config_id, True)
    allowed = db.resolve_effective_llm_access(user_id)
    assert allowed["source"] == "shared-user"
    assert config_id in allowed["allowed_shared_config_ids"]


def test_shared_llm_allowlist_group_deny_beats_group_allow(
    temp_db_path: Path, monkeypatch
):
    """Group deny takes precedence over another group's allow for the same shared config."""
    monkeypatch.setenv("ADMIN_PASSWORD", "secret123")
    db = AdminDB(str(temp_db_path))
    user_id = db.create_user("alice", "pw", display_name="Alice", is_admin=False)
    allow_group = db.create_group("allow", priority=10)
    deny_group = db.create_group("deny", priority=20)
    db.set_user_groups(user_id, [allow_group, deny_group])
    db.save_shared_llm_config(
        name="Shared One",
        api_key="shared-key",
        model="gpt-test",
        base_url="https://api.example.com/v1",
    )
    config_id = db.list_shared_llm_configs()[0]["id"]
    db.assign_shared_llm_to_group(allow_group, config_id)
    db.assign_shared_llm_to_group(deny_group, config_id)
    db.set_group_llm_allowlist(allow_group, config_id, True)
    db.set_group_llm_allowlist(deny_group, config_id, False)

    assert db.can_user_use_shared_llm(user_id, config_id) is False
    resolved = db.resolve_effective_llm_access(user_id)
    assert resolved["source"] != "shared-group"
