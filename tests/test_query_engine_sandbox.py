"""
Integration tests for sandbox routing in QueryEngine (app/query_engine.py)
and sandbox-related PluginRegistry methods (plugins/registry.py).
"""

import asyncio
import os
import sys
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
from typing import Any

# Add project root to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from plugins.base import PluginResult, TIPlugin
from plugins.registry import PluginRegistry
from models import EvidenceItem


# ── Helpers ──────────────────────────────────────────────────────


class _FakeMeta:
    """Minimal PluginMetadata-like object."""

    def __init__(self, name="test_plugin", api_key_env_var=None):
        self.name = name
        self.display_name = name
        self.version = "1.0.0"
        self.supported_types = ["ip"]
        self.requires_api_key = False
        self.api_key_env_var = api_key_env_var
        self.rate_limit = None
        self.priority = 50
        self.tags = []
        self.description = ""


class _FakePlugin:
    """Minimal plugin mock for testing."""

    def __init__(self, name="test_plugin", api_key_env_var=None):
        self.metadata = _FakeMeta(name=name, api_key_env_var=api_key_env_var)
        self.plugin_config = {}

    async def query(self, observable: str, obs_type: str) -> PluginResult:
        return PluginResult(
            source=self.metadata.name,
            ok=True,
            raw_data={"ip": observable},
            evidence=[],
        )

    def configure(self, config: dict) -> None:
        self.plugin_config = config

    def on_register(self) -> None:
        pass


class _CrashingPlugin(_FakePlugin):
    """Plugin that raises during query()."""

    async def query(self, observable: str, obs_type: str) -> PluginResult:
        raise RuntimeError("Plugin exploded!")


# ── Tests: PluginRegistry.is_sandboxed ───────────────────────────


class TestRegistryIsSandboxed:
    """Test PluginRegistry.is_sandboxed() method."""

    def test_builtin_plugin_not_sandboxed(self):
        """Builtin plugins (origin_dir=plugins/builtin) are not sandboxed."""
        registry = PluginRegistry({"plugins": {}})
        registry._plugin_origins["abuseipdb"] = "plugins/builtin"

        assert registry.is_sandboxed("abuseipdb") is False

    def test_community_plugin_is_sandboxed(self):
        """Community plugins (origin_dir=plugins/community) are sandboxed."""
        registry = PluginRegistry({"plugins": {}})
        registry._plugin_origins["threatfox"] = "plugins/community"

        assert registry.is_sandboxed("threatfox") is True

    def test_explicit_override_true(self):
        """Explicit sandboxed=True in config overrides origin-based default."""
        config = {"plugins": {"my_builtin": {"sandboxed": True}}}
        registry = PluginRegistry(config)
        registry._plugin_origins["my_builtin"] = "plugins/builtin"

        # Even though origin is builtin, explicit config wins
        assert registry.is_sandboxed("my_builtin") is True

    def test_explicit_override_false(self):
        """Explicit sandboxed=False in config overrides origin-based default."""
        config = {"plugins": {"trusted_community": {"sandboxed": False}}}
        registry = PluginRegistry(config)
        registry._plugin_origins["trusted_community"] = "plugins/community"

        # Even though origin is community, explicit config wins
        assert registry.is_sandboxed("trusted_community") is False

    def test_unknown_origin_not_sandboxed(self):
        """Plugin with empty origin (no 'community' in path) is not sandboxed."""
        registry = PluginRegistry({"plugins": {}})
        registry._plugin_origins["unknown"] = ""

        assert registry.is_sandboxed("unknown") is False

    def test_missing_plugin_not_sandboxed(self):
        """Plugin not in _plugin_origins defaults to not sandboxed."""
        registry = PluginRegistry({"plugins": {}})

        assert registry.is_sandboxed("nonexistent") is False


# ── Tests: PluginRegistry.get_sandbox_config ─────────────────────


class TestRegistryGetSandboxConfig:
    """Test PluginRegistry.get_sandbox_config() method."""

    def test_defaults(self):
        """Default sandbox config returns timeout=30 and memory_limit_mb=512."""
        registry = PluginRegistry({"plugins": {}})
        config = registry.get_sandbox_config("any_plugin")

        assert config["timeout"] == 30
        assert config["memory_limit_mb"] == 512

    def test_custom_timeout(self):
        """Per-plugin timeout override is applied."""
        plugin_config = {"plugins": {"slow_plugin": {"timeout": 60}}}
        registry = PluginRegistry(plugin_config)
        config = registry.get_sandbox_config("slow_plugin")

        assert config["timeout"] == 60
        assert config["memory_limit_mb"] == 512  # still default

    def test_custom_memory_limit(self):
        """Per-plugin memory_limit_mb override is applied."""
        plugin_config = {"plugins": {"heavy_plugin": {"memory_limit_mb": 1024}}}
        registry = PluginRegistry(plugin_config)
        config = registry.get_sandbox_config("heavy_plugin")

        assert config["timeout"] == 30  # still default
        assert config["memory_limit_mb"] == 1024

    def test_custom_both(self):
        """Both timeout and memory_limit_mb can be overridden."""
        plugin_config = {
            "plugins": {"custom_plugin": {"timeout": 120, "memory_limit_mb": 2048}}
        }
        registry = PluginRegistry(plugin_config)
        config = registry.get_sandbox_config("custom_plugin")

        assert config["timeout"] == 120
        assert config["memory_limit_mb"] == 2048


# ── Tests: QueryEngine._safe_query sandbox routing ───────────────


class TestSafeQueryRouting:
    """Test QueryEngine._safe_query() sandbox routing logic.

    We construct a minimal QueryEngine by mocking all __init__ dependencies,
    then test _safe_query() directly.
    """

    @pytest.fixture
    def engine(self):
        """Create a QueryEngine with all dependencies mocked."""
        with (
            patch("app.query_engine._load_plugin_config", return_value={"plugins": {}}),
            patch("app.query_engine.SemanticEnricher"),
            patch("app.query_engine.ReputationEngine"),
            patch("app.query_engine.VerdictEngine"),
            patch("app.query_engine.CacheStore"),
            patch("app.query_engine.ContextualRiskEngine"),
            patch("app.query_engine.NoiseEngine"),
            patch("app.query_engine.PluginRegistry") as MockRegistry,
        ):
            # Prevent discover() from scanning real directories
            MockRegistry.return_value.discover = MagicMock()
            MockRegistry.return_value.is_sandboxed = MagicMock(return_value=False)
            MockRegistry.return_value.get_sandbox_config = MagicMock(
                return_value={"timeout": 30, "memory_limit_mb": 512}
            )

            from app.query_engine import QueryEngine

            engine = QueryEngine()

        return engine

    @pytest.mark.asyncio
    async def test_trusted_plugin_runs_inprocess(self, engine):
        """Builtin (non-sandboxed) plugins call query() directly."""
        plugin = _FakePlugin(name="builtin_plugin")
        engine.registry.is_sandboxed.return_value = False

        # Replace sandbox runner with a mock so we can verify it's NOT called
        engine._sandbox_runner = MagicMock()
        engine._sandbox_runner.run = AsyncMock()

        result = await engine._safe_query(plugin, "8.8.8.8", "ip")

        assert result.ok is True
        assert result.source == "builtin_plugin"
        # Sandbox runner should NOT have been called
        engine._sandbox_runner.run.assert_not_called()

    @pytest.mark.asyncio
    async def test_community_plugin_runs_sandboxed(self, engine):
        """Community (sandboxed) plugins go through SandboxedPluginRunner."""
        plugin = _FakePlugin(name="community_plugin")
        engine.registry.is_sandboxed.return_value = True
        engine.registry.get_sandbox_config.return_value = {
            "timeout": 30,
            "memory_limit_mb": 512,
        }

        # Mock sandbox runner
        expected_result = PluginResult(
            source="community_plugin", ok=True, raw_data={"key": "val"}
        )
        engine._sandbox_runner.run = AsyncMock(return_value=expected_result)

        result = await engine._safe_query(plugin, "8.8.8.8", "ip")

        assert result.ok is True
        assert result.source == "community_plugin"
        engine._sandbox_runner.run.assert_awaited_once_with(
            plugin, "8.8.8.8", "ip", {"timeout": 30, "memory_limit_mb": 512}
        )

    @pytest.mark.asyncio
    async def test_inprocess_crash_returns_error_result(self, engine):
        """In-process plugin crash returns error PluginResult, not exception."""
        plugin = _CrashingPlugin(name="crash_plugin")
        engine.registry.is_sandboxed.return_value = False

        result = await engine._safe_query(plugin, "8.8.8.8", "ip")

        assert result.ok is False
        assert "Plugin crashed" in result.error
        assert result.source == "crash_plugin"

    @pytest.mark.asyncio
    async def test_sandboxed_crash_returns_error_result(self, engine):
        """Sandbox runner exception returns error PluginResult, not exception."""
        plugin = _FakePlugin(name="broken_sandbox")
        engine.registry.is_sandboxed.return_value = True
        engine.registry.get_sandbox_config.return_value = {
            "timeout": 30,
            "memory_limit_mb": 512,
        }
        engine._sandbox_runner.run = AsyncMock(
            side_effect=RuntimeError("Subprocess exploded")
        )

        result = await engine._safe_query(plugin, "8.8.8.8", "ip")

        assert result.ok is False
        assert "Plugin crashed" in result.error
        assert result.source == "broken_sandbox"

    @pytest.mark.asyncio
    async def test_sandbox_timeout_returns_error_result(self, engine):
        """Sandbox timeout is caught and returns error PluginResult."""
        plugin = _FakePlugin(name="slow_plugin")
        engine.registry.is_sandboxed.return_value = True
        engine.registry.get_sandbox_config.return_value = {
            "timeout": 5,
            "memory_limit_mb": 512,
        }
        engine._sandbox_runner.run = AsyncMock(side_effect=asyncio.TimeoutError())

        result = await engine._safe_query(plugin, "8.8.8.8", "ip")

        # TimeoutError is a subclass of Exception — should be caught
        assert result.ok is False
        assert "Plugin crashed" in result.error
        assert result.source == "slow_plugin"
