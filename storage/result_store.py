"""
Persistent result store for TIRE V2.

Stores query snapshots, generated reports, and plugin API keys in a
dedicated SQLite database (storage/results.db), separate from the
TTL-based cache (cache/cache.db) and the admin portal DB (admin/admin.db).

Design decisions:
  - Raw sqlite3 + WAL mode (matches existing codebase pattern).
  - Old snapshots are archived, never overwritten — enables comparison.
  - Per-API-key sharing: shared-key results can be served to all users;
    personal-key results are isolated.
  - Plugin API keys are Fernet-encrypted at rest.
  - Staleness threshold (default 7 days) triggers re-query even if data
    is persisted.
"""

import json
import logging
import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Optional

from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

# Default DB path: <project_root>/storage/results.db
_DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "results.db")

# Default staleness threshold in days
DEFAULT_STALENESS_DAYS = 7


def _utc_now_iso() -> str:
    """Return an ISO-8601 UTC timestamp string."""
    return datetime.now(UTC).isoformat()


class ResultStore:
    """SQLite-backed persistent store for query results, reports, and API keys.

    Tables:
      - query_snapshots: Archived IP query results (verdict + raw_sources).
      - stored_reports:  Generated narrative reports (HTML, per-user).
      - plugin_api_keys: Per-user and shared (admin) plugin API keys (Fernet-encrypted).
      - admin_key_policy: Admin controls for shared key usage.
    """

    def __init__(self, db_path: str | None = None, fernet_key: bytes | None = None):
        self.db_path = Path(db_path or _DEFAULT_DB_PATH).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Fernet key for encrypting API keys at rest.
        # In production this MUST come from an env var or secrets manager.
        self._fernet = self._init_fernet(fernet_key)

        self._init_db()

    # ── Connection helpers ──────────────────────────────────────────

    def _get_conn(self) -> sqlite3.Connection:
        """Open a WAL-mode connection with Row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @staticmethod
    def _init_fernet(key: bytes | None) -> Fernet:
        """Initialise the Fernet cipher.

        Priority: explicit key arg > TIRE_FERNET_KEY env var > auto-generate.
        Auto-generated keys are logged with a warning — they won't survive
        restarts (keys become unrecoverable).
        """
        if key:
            return Fernet(key)

        env_key = os.environ.get("TIRE_FERNET_KEY")
        if env_key:
            return Fernet(env_key.encode())

        generated = Fernet.generate_key()
        logger.warning(
            "No TIRE_FERNET_KEY configured — generated a temporary Fernet key. "
            "API keys stored this session will be UNRECOVERABLE after restart. "
            "Set TIRE_FERNET_KEY in .env for production use."
        )
        return Fernet(generated)

    # ── Schema ──────────────────────────────────────────────────────

    def _init_db(self) -> None:
        """Create tables and indexes if they don't exist."""
        with self._get_conn() as conn:
            conn.executescript("""
                -- Archived query snapshots (one row per query execution)
                CREATE TABLE IF NOT EXISTS query_snapshots (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip           TEXT    NOT NULL,
                    user_id      INTEGER,
                    api_key_type TEXT    NOT NULL DEFAULT 'shared',
                    verdict_json TEXT    NOT NULL,
                    sources_json TEXT,
                    final_score  INTEGER NOT NULL DEFAULT 0,
                    level        TEXT    NOT NULL DEFAULT 'Inconclusive',
                    queried_at   TEXT    NOT NULL,
                    is_archived  INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_qs_ip          ON query_snapshots(ip);
                CREATE INDEX IF NOT EXISTS idx_qs_ip_queried   ON query_snapshots(ip, queried_at);
                CREATE INDEX IF NOT EXISTS idx_qs_user         ON query_snapshots(user_id);

                -- Stored narrative reports
                CREATE TABLE IF NOT EXISTS stored_reports (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip              TEXT    NOT NULL,
                    user_id         INTEGER NOT NULL,
                    snapshot_id     INTEGER,
                    report_html     TEXT    NOT NULL,
                    llm_enhanced    INTEGER NOT NULL DEFAULT 0,
                    lang            TEXT    NOT NULL DEFAULT 'en',
                    generated_at    TEXT    NOT NULL,
                    is_archived     INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY (snapshot_id) REFERENCES query_snapshots(id)
                );

                CREATE INDEX IF NOT EXISTS idx_sr_ip_user ON stored_reports(ip, user_id);

                -- Per-user plugin API keys (Fernet-encrypted)
                CREATE TABLE IF NOT EXISTS plugin_api_keys (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id         INTEGER NOT NULL,
                    plugin_name     TEXT    NOT NULL,
                    encrypted_key   TEXT    NOT NULL,
                    updated_at      TEXT    NOT NULL,
                    UNIQUE(user_id, plugin_name)
                );

                -- Admin shared API keys (user_id = 0 by convention)
                -- Reuses plugin_api_keys with user_id = 0

                -- Policy: whether regular users may consume shared keys
                CREATE TABLE IF NOT EXISTS admin_key_policy (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    allow_shared_keys   INTEGER NOT NULL DEFAULT 1,
                    updated_at          TEXT    NOT NULL
                );
            """)
            # Ensure a default policy row exists
            row = conn.execute("SELECT COUNT(*) FROM admin_key_policy").fetchone()
            if row[0] == 0:
                conn.execute(
                    "INSERT INTO admin_key_policy (allow_shared_keys, updated_at) VALUES (1, ?)",
                    (_utc_now_iso(),),
                )

    # ── Query Snapshots ─────────────────────────────────────────────

    def save_snapshot(
        self,
        ip: str,
        verdict_json: str,
        sources_json: str | None,
        final_score: int,
        level: str,
        user_id: int | None = None,
        api_key_type: str = "shared",
    ) -> int:
        """Persist a query snapshot. Returns the new row id."""
        now = _utc_now_iso()
        with self._get_conn() as conn:
            cursor = conn.execute(
                """INSERT INTO query_snapshots
                   (ip, user_id, api_key_type, verdict_json, sources_json,
                    final_score, level, queried_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ip,
                    user_id,
                    api_key_type,
                    verdict_json,
                    sources_json,
                    final_score,
                    level,
                    now,
                ),
            )
            return cursor.lastrowid  # type: ignore[return-value]

    def get_latest_snapshot(
        self,
        ip: str,
        user_id: int | None = None,
        api_key_type: str = "shared",
        staleness_days: int = DEFAULT_STALENESS_DAYS,
    ) -> Optional[dict[str, Any]]:
        """Return the most recent non-stale snapshot for an IP.

        For shared API keys, any user's snapshot is returned.
        For personal API keys, only the requesting user's snapshot is returned.

        Returns None if no snapshot exists or the latest one is stale.
        """
        cutoff = (datetime.now(UTC) - timedelta(days=staleness_days)).isoformat()

        with self._get_conn() as conn:
            if api_key_type == "shared":
                row = conn.execute(
                    """SELECT * FROM query_snapshots
                       WHERE ip = ? AND api_key_type = 'shared'
                         AND queried_at > ? AND is_archived = 0
                       ORDER BY queried_at DESC LIMIT 1""",
                    (ip, cutoff),
                ).fetchone()
            else:
                row = conn.execute(
                    """SELECT * FROM query_snapshots
                       WHERE ip = ? AND user_id = ? AND api_key_type = 'personal'
                         AND queried_at > ? AND is_archived = 0
                       ORDER BY queried_at DESC LIMIT 1""",
                    (ip, user_id, cutoff),
                ).fetchone()

        return dict(row) if row else None

    def get_snapshot_history(self, ip: str, limit: int = 20) -> list[dict[str, Any]]:
        """Return all snapshots for an IP, newest first (for comparison)."""
        with self._get_conn() as conn:
            rows = conn.execute(
                """SELECT id, ip, user_id, api_key_type, final_score, level,
                          queried_at, is_archived
                   FROM query_snapshots
                   WHERE ip = ?
                   ORDER BY queried_at DESC
                   LIMIT ?""",
                (ip, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_snapshot_by_id(self, snapshot_id: int) -> Optional[dict[str, Any]]:
        """Retrieve a single snapshot by its ID (for side-by-side diff)."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM query_snapshots WHERE id = ?",
                (snapshot_id,),
            ).fetchone()
        return dict(row) if row else None

    def archive_snapshots(self, ip: str) -> int:
        """Mark all current (non-archived) snapshots for an IP as archived.

        Called before saving a new refresh result to preserve history.
        Returns the number of rows archived.
        """
        now = _utc_now_iso()
        with self._get_conn() as conn:
            cursor = conn.execute(
                """UPDATE query_snapshots
                   SET is_archived = 1
                   WHERE ip = ? AND is_archived = 0""",
                (ip,),
            )
            return cursor.rowcount

    # ── Stored Reports ──────────────────────────────────────────────

    def save_report(
        self,
        ip: str,
        user_id: int,
        report_html: str,
        llm_enhanced: bool = False,
        lang: str = "en",
        snapshot_id: int | None = None,
    ) -> int:
        """Persist a generated report. Returns the new row id."""
        now = _utc_now_iso()
        with self._get_conn() as conn:
            cursor = conn.execute(
                """INSERT INTO stored_reports
                   (ip, user_id, snapshot_id, report_html, llm_enhanced, lang, generated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (ip, user_id, snapshot_id, report_html, int(llm_enhanced), lang, now),
            )
            return cursor.lastrowid  # type: ignore[return-value]

    def get_latest_report(
        self,
        ip: str,
        user_id: int,
        lang: str = "en",
    ) -> Optional[dict[str, Any]]:
        """Return the latest non-archived report for an IP+user+lang combo.

        Reports are per-user because different users have different LLM settings.
        """
        with self._get_conn() as conn:
            row = conn.execute(
                """SELECT * FROM stored_reports
                   WHERE ip = ? AND user_id = ? AND lang = ? AND is_archived = 0
                   ORDER BY generated_at DESC LIMIT 1""",
                (ip, user_id, lang),
            ).fetchone()
        return dict(row) if row else None

    def get_report_history(
        self, ip: str, user_id: int, limit: int = 20
    ) -> list[dict[str, Any]]:
        """Return report history for comparison."""
        with self._get_conn() as conn:
            rows = conn.execute(
                """SELECT id, ip, user_id, snapshot_id, llm_enhanced, lang,
                          generated_at, is_archived
                   FROM stored_reports
                   WHERE ip = ? AND user_id = ?
                   ORDER BY generated_at DESC
                   LIMIT ?""",
                (ip, user_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_report_by_id(self, report_id: int) -> Optional[dict[str, Any]]:
        """Retrieve a single report by ID (for diff view)."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM stored_reports WHERE id = ?",
                (report_id,),
            ).fetchone()
        return dict(row) if row else None

    def archive_reports(self, ip: str, user_id: int) -> int:
        """Archive all current reports for an IP+user before regeneration."""
        with self._get_conn() as conn:
            cursor = conn.execute(
                """UPDATE stored_reports
                   SET is_archived = 1
                   WHERE ip = ? AND user_id = ? AND is_archived = 0""",
                (ip, user_id),
            )
            return cursor.rowcount

    # ── Plugin API Keys (Fernet-encrypted) ──────────────────────────

    def save_plugin_api_key(self, user_id: int, plugin_name: str, api_key: str) -> None:
        """Store or update an encrypted plugin API key for a user.

        Use user_id=0 for admin shared keys.
        """
        now = _utc_now_iso()
        encrypted = self._fernet.encrypt(api_key.encode()).decode()
        with self._get_conn() as conn:
            conn.execute(
                """INSERT INTO plugin_api_keys (user_id, plugin_name, encrypted_key, updated_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(user_id, plugin_name) DO UPDATE SET
                     encrypted_key = excluded.encrypted_key,
                     updated_at = excluded.updated_at""",
                (user_id, plugin_name, encrypted, now),
            )

    def get_plugin_api_key(self, user_id: int, plugin_name: str) -> Optional[str]:
        """Retrieve and decrypt a plugin API key for a specific user.

        Returns None if no key is stored.
        """
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT encrypted_key FROM plugin_api_keys WHERE user_id = ? AND plugin_name = ?",
                (user_id, plugin_name),
            ).fetchone()
        if not row:
            return None
        try:
            return self._fernet.decrypt(row["encrypted_key"].encode()).decode()
        except Exception:
            logger.error(
                "Failed to decrypt API key for user=%s plugin=%s — key may be "
                "from a previous Fernet key. User must re-enter.",
                user_id,
                plugin_name,
            )
            return None

    def resolve_plugin_api_key(
        self, user_id: int, plugin_name: str, env_var: str | None = None
    ) -> tuple[Optional[str], str]:
        """Resolve the effective API key using the fallback chain.

        Fallback order: user_key -> shared_admin_key -> env_var -> None.

        Returns:
            (api_key, source) where source is one of:
            'user', 'shared', 'env', 'none'
        """
        # 1. User's personal key
        user_key = self.get_plugin_api_key(user_id, plugin_name)
        if user_key:
            return user_key, "user"

        # 2. Shared admin key (user_id=0), if policy allows
        if self.is_shared_keys_allowed():
            shared_key = self.get_plugin_api_key(0, plugin_name)
            if shared_key:
                return shared_key, "shared"

        # 3. Environment variable fallback
        if env_var:
            env_val = os.environ.get(env_var)
            if env_val:
                return env_val, "env"

        return None, "none"

    def delete_plugin_api_key(self, user_id: int, plugin_name: str) -> None:
        """Remove a stored plugin API key."""
        with self._get_conn() as conn:
            conn.execute(
                "DELETE FROM plugin_api_keys WHERE user_id = ? AND plugin_name = ?",
                (user_id, plugin_name),
            )

    def list_plugin_api_keys(self, user_id: int) -> list[dict[str, Any]]:
        """List all plugin API keys for a user (keys are NOT decrypted)."""
        with self._get_conn() as conn:
            rows = conn.execute(
                """SELECT plugin_name, updated_at
                   FROM plugin_api_keys
                   WHERE user_id = ?
                   ORDER BY plugin_name""",
                (user_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Admin Key Policy ────────────────────────────────────────────

    def is_shared_keys_allowed(self) -> bool:
        """Check whether the admin allows regular users to use shared keys."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT allow_shared_keys FROM admin_key_policy ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return bool(row and row["allow_shared_keys"])

    def set_shared_keys_policy(self, allowed: bool) -> None:
        """Update the shared-key policy."""
        now = _utc_now_iso()
        with self._get_conn() as conn:
            conn.execute(
                """UPDATE admin_key_policy
                   SET allow_shared_keys = ?, updated_at = ?
                   WHERE id = (SELECT id FROM admin_key_policy ORDER BY id DESC LIMIT 1)""",
                (int(allowed), now),
            )


# Singleton instance
result_store = ResultStore()
