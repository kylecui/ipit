"""Regression tests for RDAP plugin redirect handling."""

from __future__ import annotations

import asyncio

from plugins.base import PluginMetadata, TIPlugin
from plugins.builtin.rdap import RDAPPlugin


class _DummyPlugin(TIPlugin):
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(name="dummy", display_name="Dummy", version="1.0.0")

    async def query(self, observable: str, obs_type: str):
        raise NotImplementedError


def test_make_request_passes_follow_redirects_to_httpx(monkeypatch) -> None:
    """Shared plugin request helper should propagate redirect-following explicitly."""

    captured: dict[str, object] = {}

    class _FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, str]:
            return {"status": "ok"}

    class _FakeAsyncClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb) -> None:
            return None

        async def get(self, url: str, **kwargs):
            captured["url"] = url
            captured.update(kwargs)
            return _FakeResponse()

    monkeypatch.setattr("plugins.base.AsyncClient", _FakeAsyncClient)

    result = asyncio.run(
        _DummyPlugin()._make_request(
            "https://example.test/rdap",
            follow_redirects=True,
        )
    )

    assert result == {"ok": True, "data": {"status": "ok"}, "error": None}
    assert captured["url"] == "https://example.test/rdap"
    assert captured["follow_redirects"] is True


def test_rdap_query_enables_redirect_following(monkeypatch) -> None:
    """RDAP lookups should opt into redirect following for registry handoff."""
    plugin = RDAPPlugin()
    captured: dict[str, object] = {}

    async def _fake_make_request(url: str, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return {
            "ok": True,
            "data": {
                "handle": "NET-TEST",
                "startAddress": "1.2.3.0",
                "endAddress": "1.2.3.255",
                "ipVersion": "v4",
                "name": "TEST-NET",
                "country": "NL",
                "cidr0_cidrs": [{"v4prefix": "1.2.3.0", "length": 24}],
            },
            "error": None,
        }

    monkeypatch.setattr(plugin, "_make_request", _fake_make_request)

    result = asyncio.run(plugin.query("1.2.3.4", "ip"))

    assert captured["url"] == "https://rdap.arin.net/registry/ip/1.2.3.4"
    assert captured["follow_redirects"] is True
    assert result.ok is True
    assert result.raw_data["name"] == "TEST-NET"
    assert result.normalized_data == {
        "organization": "TEST-NET",
        "country": "NL",
        "network": "1.2.3.0/24",
    }
