"""Regression tests for result_store accessor usage."""

from __future__ import annotations

from types import SimpleNamespace

from app.query_engine import QueryEngine


def test_query_engine_uses_current_result_store_singleton(monkeypatch) -> None:
    """QueryEngine should resolve the current result_store singleton at call time."""
    captured = {}

    def _fake_archive_snapshots(ip: str) -> int:
        captured["ip"] = ip
        return 0

    fake_store = SimpleNamespace(
        archive_snapshots=_fake_archive_snapshots,
        is_configured_only=lambda: False,
        get_plugin_api_key=lambda *args, **kwargs: None,
        resolve_plugin_api_key=lambda *args, **kwargs: (None, "none"),
        record_plugin_usage=lambda **kwargs: captured.setdefault("usage", []).append(
            kwargs
        ),
        save_snapshot=lambda **kwargs: None,
    )

    monkeypatch.setattr("storage.result_store.result_store", fake_store)

    engine = QueryEngine()

    async def _fake_collect_ip_data(ip, refresh=False, user_id=None):
        return None, [], "shared"

    async def _fake_enrich_ip_profile(profile):
        return profile

    async def _fake_analyze_ip_profile(
        profile,
        plugin_evidence,
        context=None,
        refresh=False,
        user_id=None,
        sharing_scope="system",
    ):
        return SimpleNamespace()

    monkeypatch.setattr(engine, "_collect_ip_data", _fake_collect_ip_data)
    monkeypatch.setattr(engine, "_enrich_ip_profile", _fake_enrich_ip_profile)
    monkeypatch.setattr(engine, "_analyze_ip_profile", _fake_analyze_ip_profile)

    from models import Observable
    import asyncio

    asyncio.run(engine.analyze(Observable(type="ip", value="8.8.8.8"), refresh=True))

    assert captured["ip"] == "8.8.8.8"


def test_query_engine_records_plugin_usage_with_key_scope(monkeypatch) -> None:
    """Plugin execution should persist usage metadata through the result-store singleton."""
    captured: list[dict[str, object]] = []

    fake_store = SimpleNamespace(
        is_configured_only=lambda: False,
        is_shared_keys_allowed=lambda: True,
        get_plugin_api_key=lambda *args, **kwargs: None,
        resolve_plugin_api_key=lambda *args, **kwargs: ("shared-key", "shared"),
        record_plugin_usage=lambda **kwargs: captured.append(kwargs),
    )
    monkeypatch.setattr("storage.result_store.result_store", fake_store)

    engine = QueryEngine()

    class _FakePlugin:
        metadata = SimpleNamespace(
            name="threatbook",
            requires_api_key=True,
            api_key_env_var="THREATBOOK_API_KEY",
        )

        def set_api_key_override(self, key):
            self.api_key = key

        async def query(self, observable, obs_type):
            from plugins.base import PluginResult

            return PluginResult(
                source="threatbook",
                ok=True,
                raw_data={},
                normalized_data={},
                evidence=[],
            )

    monkeypatch.setattr(
        engine.registry, "get_enabled", lambda obs_type: [_FakePlugin()]
    )
    monkeypatch.setattr(engine.registry, "is_sandboxed", lambda name: False)

    import asyncio

    asyncio.run(engine._collect_ip_data("8.8.8.8", refresh=True, user_id=3))

    assert captured
    assert captured[0]["plugin_name"] == "threatbook"
    assert captured[0]["user_id"] == 3
    assert captured[0]["key_scope"] == "shared"
