"""
Unit tests for the SandboxedPluginRunner (plugins/sandbox.py).
"""

import asyncio
import json
import os
import sys
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

# Add project root to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from plugins.sandbox import SandboxedPluginRunner
from plugins.base import PluginResult, PluginMetadata
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


def _make_success_data():
    """Return a valid subprocess JSON output dict."""
    return {
        "ok": True,
        "result": {
            "source": "test_plugin",
            "ok": True,
            "raw_data": {"foo": "bar"},
            "normalized_data": None,
            "evidence": [
                {
                    "source": "test_plugin",
                    "category": "reputation",
                    "severity": "high",
                    "title": "Test finding",
                    "detail": "Something bad",
                    "score_delta": 25,
                    "confidence": 0.9,
                    "raw": {},
                }
            ],
            "error": None,
        },
    }


# ── Tests ────────────────────────────────────────────────────────


class TestSandboxedPluginRunnerRun:
    """Test SandboxedPluginRunner.run() method."""

    @pytest.fixture
    def runner(self):
        return SandboxedPluginRunner()

    @pytest.fixture
    def plugin(self):
        return _FakePlugin()

    @pytest.fixture
    def sandbox_config(self):
        return {"timeout": 30, "memory_limit_mb": 512}

    @pytest.mark.asyncio
    async def test_run_success(self, runner, plugin, sandbox_config):
        """Successful sandboxed execution returns parsed PluginResult."""
        success_data = _make_success_data()

        with patch.object(
            runner, "_spawn_and_communicate", new_callable=AsyncMock
        ) as mock_spawn:
            mock_spawn.return_value = success_data
            result = await runner.run(plugin, "8.8.8.8", "ip", sandbox_config)

        assert result.ok is True
        assert result.source == "test_plugin"
        assert len(result.evidence) == 1
        assert isinstance(result.evidence[0], EvidenceItem)
        assert result.evidence[0].score_delta == 25
        assert result.evidence[0].severity == "high"

    @pytest.mark.asyncio
    async def test_run_timeout(self, runner, plugin, sandbox_config):
        """Timeout in subprocess returns error PluginResult."""
        with patch.object(
            runner, "_spawn_and_communicate", new_callable=AsyncMock
        ) as mock_spawn:
            mock_spawn.side_effect = asyncio.TimeoutError()
            result = await runner.run(plugin, "8.8.8.8", "ip", sandbox_config)

        assert result.ok is False
        assert "timed out" in result.error.lower()
        assert result.source == "test_plugin"

    @pytest.mark.asyncio
    async def test_run_crash(self, runner, plugin, sandbox_config):
        """Generic exception in subprocess returns error PluginResult."""
        with patch.object(
            runner, "_spawn_and_communicate", new_callable=AsyncMock
        ) as mock_spawn:
            mock_spawn.side_effect = RuntimeError("subprocess died")
            result = await runner.run(plugin, "8.8.8.8", "ip", sandbox_config)

        assert result.ok is False
        assert "Sandbox execution failed" in result.error
        assert result.source == "test_plugin"


class TestParseResult:
    """Test SandboxedPluginRunner._parse_result() static method."""

    def test_parse_result_success(self):
        """Valid success data is parsed into PluginResult with EvidenceItems."""
        data = _make_success_data()
        result = SandboxedPluginRunner._parse_result(data, "test_plugin")

        assert result.ok is True
        assert result.source == "test_plugin"
        assert result.raw_data == {"foo": "bar"}
        assert len(result.evidence) == 1
        assert result.evidence[0].title == "Test finding"
        assert result.evidence[0].confidence == 0.9

    def test_parse_result_error(self):
        """Error data is parsed into failed PluginResult."""
        data = {"ok": False, "error": "import failed", "traceback": "File ..."}
        result = SandboxedPluginRunner._parse_result(data, "test_plugin")

        assert result.ok is False
        assert result.source == "test_plugin"
        assert result.error == "import failed"

    def test_parse_result_error_no_traceback(self):
        """Error data without traceback still works."""
        data = {"ok": False, "error": "something broke"}
        result = SandboxedPluginRunner._parse_result(data, "my_plugin")

        assert result.ok is False
        assert result.error == "something broke"

    def test_parse_result_multiple_evidence(self):
        """Multiple evidence items are all parsed."""
        data = {
            "ok": True,
            "result": {
                "source": "multi",
                "ok": True,
                "raw_data": None,
                "normalized_data": None,
                "evidence": [
                    {
                        "source": "multi",
                        "category": "reputation",
                        "severity": "high",
                        "title": "Finding 1",
                        "detail": "Detail 1",
                        "score_delta": 10,
                        "confidence": 0.8,
                        "raw": {},
                    },
                    {
                        "source": "multi",
                        "category": "context",
                        "severity": "low",
                        "title": "Finding 2",
                        "detail": "Detail 2",
                        "score_delta": 5,
                        "confidence": 0.5,
                        "raw": {},
                    },
                ],
                "error": None,
            },
        }
        result = SandboxedPluginRunner._parse_result(data, "multi")

        assert result.ok is True
        assert len(result.evidence) == 2
        assert result.evidence[0].title == "Finding 1"
        assert result.evidence[1].title == "Finding 2"


class TestBuildEnvVars:
    """Test SandboxedPluginRunner._build_env_vars() static method."""

    def test_includes_system_keys(self):
        """System keys present in os.environ are included."""
        plugin = _FakePlugin(api_key_env_var=None)
        env = {"PATH": "/usr/bin", "HOME": "/home/user", "RANDOM_VAR": "nope"}

        with patch.dict(os.environ, env, clear=True):
            result = SandboxedPluginRunner._build_env_vars(plugin)

        assert result["PATH"] == "/usr/bin"
        assert result["HOME"] == "/home/user"
        assert "RANDOM_VAR" not in result

    def test_includes_plugin_api_key(self):
        """Plugin's own API key is included, other secrets are not."""
        plugin = _FakePlugin(api_key_env_var="MY_PLUGIN_KEY")
        env = {
            "PATH": "/usr/bin",
            "MY_PLUGIN_KEY": "secret123",
            "LLM_API_KEY": "llm_secret",
            "SESSION_SECRET_KEY": "session_secret",
            "OTHER_PLUGIN_KEY": "other_secret",
        }

        with patch.dict(os.environ, env, clear=True):
            result = SandboxedPluginRunner._build_env_vars(plugin)

        assert result["MY_PLUGIN_KEY"] == "secret123"
        assert "LLM_API_KEY" not in result
        assert "SESSION_SECRET_KEY" not in result
        assert "OTHER_PLUGIN_KEY" not in result

    def test_no_api_key_env_var(self):
        """Plugin without api_key_env_var only gets system keys."""
        plugin = _FakePlugin(api_key_env_var=None)
        env = {"PATH": "/usr/bin", "SOME_SECRET": "hidden"}

        with patch.dict(os.environ, env, clear=True):
            result = SandboxedPluginRunner._build_env_vars(plugin)

        assert "PATH" in result
        assert "SOME_SECRET" not in result

    def test_missing_api_key_in_environ(self):
        """If plugin's API key env var is not set, it's omitted (not error)."""
        plugin = _FakePlugin(api_key_env_var="MISSING_KEY")
        env = {"PATH": "/usr/bin"}

        with patch.dict(os.environ, env, clear=True):
            result = SandboxedPluginRunner._build_env_vars(plugin)

        assert "MISSING_KEY" not in result


class TestGetModulePath:
    """Test SandboxedPluginRunner._get_module_path() static method."""

    def test_returns_module_string(self):
        """Returns the __module__ of the plugin's class."""
        plugin = _FakePlugin()
        path = SandboxedPluginRunner._get_module_path(plugin)
        # _FakePlugin is defined in this test module
        assert path == __name__ or "test_sandbox" in path


class TestSpawnAndCommunicate:
    """Test SandboxedPluginRunner._spawn_and_communicate() method."""

    @pytest.fixture
    def runner(self):
        return SandboxedPluginRunner()

    def _make_mock_proc(self, stdout=b"", stderr=b"", returncode=0):
        """Create a mock asyncio subprocess."""
        proc = MagicMock()
        proc.communicate = AsyncMock(return_value=(stdout, stderr))
        proc.returncode = returncode
        proc.kill = MagicMock()
        proc.wait = AsyncMock()
        return proc

    @pytest.mark.asyncio
    async def test_valid_json_output(self, runner):
        """Valid JSON on stdout with returncode 0 is parsed correctly."""
        data = {"ok": True, "result": {"source": "x"}}
        proc = self._make_mock_proc(stdout=json.dumps(data).encode(), returncode=0)

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock
        ) as mock_exec:
            mock_exec.return_value = proc
            result = await runner._spawn_and_communicate(
                {"test": "request"}, timeout=30, plugin_name="test"
            )

        assert result == data

    @pytest.mark.asyncio
    async def test_nonzero_exit_with_json_error(self, runner):
        """Non-zero exit with JSON error on stdout returns the parsed dict."""
        error_data = {"ok": False, "error": "crashed"}
        proc = self._make_mock_proc(
            stdout=json.dumps(error_data).encode(), returncode=1
        )

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock
        ) as mock_exec:
            mock_exec.return_value = proc
            result = await runner._spawn_and_communicate(
                {"test": "request"}, timeout=30, plugin_name="test"
            )

        # Should return parsed JSON error dict
        assert result == error_data

    @pytest.mark.asyncio
    async def test_nonzero_exit_no_json(self, runner):
        """Non-zero exit with non-JSON output raises RuntimeError."""
        proc = self._make_mock_proc(
            stdout=b"segfault", stderr=b"core dumped", returncode=139
        )

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock
        ) as mock_exec:
            mock_exec.return_value = proc
            with pytest.raises(RuntimeError, match="Subprocess exited with code 139"):
                await runner._spawn_and_communicate(
                    {"test": "request"}, timeout=30, plugin_name="test"
                )

    @pytest.mark.asyncio
    async def test_empty_output(self, runner):
        """Empty stdout with returncode 0 raises RuntimeError."""
        proc = self._make_mock_proc(stdout=b"", returncode=0)

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock
        ) as mock_exec:
            mock_exec.return_value = proc
            with pytest.raises(RuntimeError, match="no output"):
                await runner._spawn_and_communicate(
                    {"test": "request"}, timeout=30, plugin_name="test"
                )

    @pytest.mark.asyncio
    async def test_invalid_json_output(self, runner):
        """Non-JSON stdout with returncode 0 raises RuntimeError."""
        proc = self._make_mock_proc(stdout=b"not valid json{{{", returncode=0)

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock
        ) as mock_exec:
            mock_exec.return_value = proc
            with pytest.raises(RuntimeError, match="Invalid JSON"):
                await runner._spawn_and_communicate(
                    {"test": "request"}, timeout=30, plugin_name="test"
                )

    @pytest.mark.asyncio
    async def test_timeout_kills_process(self, runner):
        """TimeoutError kills the subprocess and re-raises."""
        proc = MagicMock()
        proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        proc.kill = MagicMock()
        proc.wait = AsyncMock()

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock
        ) as mock_exec:
            mock_exec.return_value = proc
            with pytest.raises(asyncio.TimeoutError):
                await runner._spawn_and_communicate(
                    {"test": "request"}, timeout=5, plugin_name="test"
                )

        proc.kill.assert_called_once()
        proc.wait.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_stderr_logged(self, runner):
        """Subprocess stderr is captured without affecting the result."""
        data = {"ok": True, "result": {"source": "x"}}
        proc = self._make_mock_proc(
            stdout=json.dumps(data).encode(),
            stderr=b"DEBUG: some log line\nWARNING: another line",
            returncode=0,
        )

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock
        ) as mock_exec:
            mock_exec.return_value = proc
            result = await runner._spawn_and_communicate(
                {"test": "request"}, timeout=30, plugin_name="test"
            )

        # Result should be unaffected by stderr content
        assert result == data
