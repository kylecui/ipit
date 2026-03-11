"""
SQLite database for admin portal — users, settings, and audit log.

Follows the existing raw sqlite3 pattern from storage/sqlite_store.py.
Separate DB file (admin/admin.db) to avoid coupling with cache.
"""

import json
import logging
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Optional

import bcrypt

logger = logging.getLogger(__name__)

# Default DB path relative to project root
_DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "admin", "admin.db")


def _utc_now_iso() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(UTC).isoformat()


class AdminDB:
    """SQLite-backed admin database for users and settings."""

    def __init__(self, db_path: str | None = None):
        self.db_path = Path(db_path or _DEFAULT_DB_PATH).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        """Create tables if they don't exist."""
        with self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    username    TEXT    UNIQUE NOT NULL,
                    password_hash TEXT  NOT NULL,
                    display_name TEXT   NOT NULL DEFAULT '',
                    is_admin    INTEGER NOT NULL DEFAULT 0,
                    is_active   INTEGER NOT NULL DEFAULT 1,
                    preferences TEXT    NOT NULL DEFAULT '{}',
                    created_at  TEXT    NOT NULL,
                    updated_at  TEXT    NOT NULL
                );

                CREATE TABLE IF NOT EXISTS llm_settings (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id     INTEGER NOT NULL UNIQUE,
                    api_key     TEXT    DEFAULT '',
                    model       TEXT    NOT NULL DEFAULT 'gpt-4o',
                    base_url    TEXT    NOT NULL DEFAULT 'https://api.openai.com/v1',
                    updated_at  TEXT    NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id     INTEGER,
                    action      TEXT    NOT NULL,
                    detail      TEXT    DEFAULT '',
                    created_at  TEXT    NOT NULL
                );
            """)

    # ── User CRUD ───────────────────────────────────────────────

    def create_user(
        self,
        username: str,
        password: str,
        display_name: str = "",
        is_admin: bool = False,
    ) -> int:
        """Create a new user. Returns user id."""
        now = _utc_now_iso()
        password_hash = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
        with self._get_conn() as conn:
            cursor = conn.execute(
                """INSERT INTO users
                   (username, password_hash, display_name, is_admin, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    username,
                    password_hash,
                    display_name or username,
                    int(is_admin),
                    now,
                    now,
                ),
            )
            return cursor.lastrowid  # type: ignore[return-value]

    def get_user_by_username(self, username: str) -> Optional[dict[str, Any]]:
        """Get user by username."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
        return dict(row) if row else None

    def get_user_by_id(self, user_id: int) -> Optional[dict[str, Any]]:
        """Get user by id."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_users(self) -> list[dict[str, Any]]:
        """List all users."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT id, username, display_name, is_admin, is_active, created_at FROM users ORDER BY id"
            ).fetchall()
        return [dict(r) for r in rows]

    def verify_password(self, username: str, password: str) -> Optional[dict[str, Any]]:
        """Verify username/password. Returns user dict or None."""
        user = self.get_user_by_username(username)
        if not user or not user.get("is_active"):
            return None
        if bcrypt.checkpw(
            password.encode("utf-8"),
            user["password_hash"].encode("utf-8"),
        ):
            return user
        return None

    def update_password(self, user_id: int, new_password: str) -> None:
        """Update user password."""
        now = _utc_now_iso()
        password_hash = bcrypt.hashpw(
            new_password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
        with self._get_conn() as conn:
            conn.execute(
                "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
                (password_hash, now, user_id),
            )

    def update_profile(
        self,
        user_id: int,
        display_name: str | None = None,
        preferences: dict | None = None,
    ) -> None:
        """Update user profile fields."""
        now = _utc_now_iso()
        updates = ["updated_at = ?"]
        params: list[Any] = [now]
        if display_name is not None:
            updates.append("display_name = ?")
            params.append(display_name)
        if preferences is not None:
            updates.append("preferences = ?")
            params.append(json.dumps(preferences))
        params.append(user_id)
        with self._get_conn() as conn:
            conn.execute(
                f"UPDATE users SET {', '.join(updates)} WHERE id = ?",
                params,
            )

    def delete_user(self, user_id: int) -> None:
        """Delete a user."""
        with self._get_conn() as conn:
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))

    # ── LLM Settings ────────────────────────────────────────────

    def get_llm_settings(self, user_id: int) -> dict[str, Any]:
        """Get LLM settings for a user. Returns defaults if none saved."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM llm_settings WHERE user_id = ?", (user_id,)
            ).fetchone()
        if row:
            return dict(row)
        # Return defaults from app config
        from app.config import settings

        return {
            "user_id": user_id,
            "api_key": settings.llm_api_key or "",
            "model": settings.llm_model,
            "base_url": settings.llm_base_url,
        }

    def save_llm_settings(
        self,
        user_id: int,
        api_key: str = "",
        model: str = "gpt-4o",
        base_url: str = "https://api.openai.com/v1",
    ) -> None:
        """Save or update LLM settings for a user."""
        now = _utc_now_iso()
        with self._get_conn() as conn:
            conn.execute(
                """INSERT INTO llm_settings (user_id, api_key, model, base_url, updated_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(user_id) DO UPDATE SET
                     api_key = excluded.api_key,
                     model = excluded.model,
                     base_url = excluded.base_url,
                     updated_at = excluded.updated_at""",
                (user_id, api_key, model, base_url, now),
            )

    # ── Audit Log ───────────────────────────────────────────────

    def log_action(self, user_id: int | None, action: str, detail: str = "") -> None:
        """Record an audit entry."""
        now = _utc_now_iso()
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO audit_log (user_id, action, detail, created_at) VALUES (?, ?, ?, ?)",
                (user_id, action, detail, now),
            )

    def get_recent_logs(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get recent audit log entries."""
        with self._get_conn() as conn:
            rows = conn.execute(
                """SELECT a.*, u.username FROM audit_log a
                   LEFT JOIN users u ON a.user_id = u.id
                   ORDER BY a.id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Bootstrap ───────────────────────────────────────────────

    def ensure_admin_exists(self) -> None:
        """Create default admin user if no users exist.

        This runs during application startup and must be safe under
        multi-worker startup races against a persisted database.
        """
        default_pw = os.environ.get("ADMIN_PASSWORD", "admin")
        now = _utc_now_iso()
        password_hash = bcrypt.hashpw(
            default_pw.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

        with self._get_conn() as conn:
            cursor = conn.execute(
                """INSERT INTO users
                   (username, password_hash, display_name, is_admin, created_at, updated_at)
                   SELECT ?, ?, ?, ?, ?, ?
                   WHERE NOT EXISTS (SELECT 1 FROM users)
                """,
                (
                    "admin",
                    password_hash,
                    "Administrator",
                    1,
                    now,
                    now,
                ),
            )

        if cursor.rowcount:
            logger.info(
                "Created default admin user (username: admin). "
                "Change the password after first login!"
            )


# Singleton instance
admin_db = AdminDB()
