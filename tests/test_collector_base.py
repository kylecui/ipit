"""Regression tests for shared collector HTTP request behavior."""

from __future__ import annotations

import asyncio

from collectors.base import BaseCollector


class _DummyCollector(BaseCollector):
    def __init__(self) -> None:
        super().__init__("dummy")

    async def query(self, observable: str):
        raise NotImplementedError


def test_make_request_passes_follow_redirects_to_httpx(monkeypatch) -> None:
    """Collector base helper should forward explicit redirect behavior to httpx."""
    captured = {}

    class _FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self):
            return {"status": "ok"}

    class _FakeAsyncClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb) -> None:
            return None

        async def get(self, url, **kwargs):
            captured["url"] = url
            captured.update(kwargs)
            return _FakeResponse()

    monkeypatch.setattr("collectors.base.AsyncClient", _FakeAsyncClient)

    result = asyncio.run(
        _DummyCollector()._make_request(
            "https://example.test/rdap",
            follow_redirects=True,
        )
    )

    assert result == {"ok": True, "data": {"status": "ok"}, "error": None}
    assert captured["url"] == "https://example.test/rdap"
    assert captured["follow_redirects"] is True
