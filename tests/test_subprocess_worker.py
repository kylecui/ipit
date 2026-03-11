"""
Unit tests for the subprocess worker (plugins/_subprocess_worker.py).
"""

import asyncio
import json
import os
import sys
from contextlib import suppress
from typing import Any
import pytest
from dataclasses import dataclass, field
from unittest.mock import AsyncMock, MagicMock, patch

# Add project root to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from plugins._subprocess_worker import (
    _apply_resource_limits,
    _serialize_result,
    _write_error,
    main,
    _run_plugin,
)


# ── Helpers ──────────────────────────────────────────────────────


class _FakeEvidenceItem:
    """Minimal EvidenceItem-like object with model_dump()."""

    def __init__(self, source="test", title="finding"):
        self.source = source
        self.title = title

    def model_dump(self):
        return {
            "source": self.source,
            "category": "reputation",
            "severity": "high",
            "title": self.title,
            "detail": "test detail",
            "score_delta": 10,
            "confidence": 0.8,
            "raw": {},
        }


@dataclass
class _FakePluginResult:
    """Minimal PluginResult-like dataclass."""

    source: str = "test_plugin"
    ok: bool = True
    raw_data: dict[str, Any] | None = None
    normalized_data: dict[str, Any] | None = None
    evidence: list[Any] = field(default_factory=list)
    error: str | None = None


# ── Tests: _serialize_result ─────────────────────────────────────


class TestSerializeResult:
    """Test _serialize_result() function."""

    def test_basic_serialization(self):
        """All PluginResult fields are serialized to dict."""
        result = _FakePluginResult(
            source="my_plugin",
            ok=True,
            raw_data={"foo": "bar"},
            normalized_data={"org": "ACME"},
            evidence=[],
            error=None,
        )
        serialized = _serialize_result(result)

        assert serialized["source"] == "my_plugin"
        assert serialized["ok"] is True
        assert serialized["raw_data"] == {"foo": "bar"}
        assert serialized["normalized_data"] == {"org": "ACME"}
        assert serialized["evidence"] == []
        assert serialized["error"] is None

    def test_evidence_calls_model_dump(self):
        """EvidenceItem objects are serialized via .model_dump()."""
        ev = _FakeEvidenceItem(source="test_src", title="Bad IP")
        result = _FakePluginResult(evidence=[ev])
        serialized = _serialize_result(result)

        assert len(serialized["evidence"]) == 1
        assert serialized["evidence"][0]["source"] == "test_src"
        assert serialized["evidence"][0]["title"] == "Bad IP"
        assert serialized["evidence"][0]["score_delta"] == 10

    def test_error_result_serialization(self):
        """Error results serialize ok=False and error message."""
        result = _FakePluginResult(ok=False, error="API down")
        serialized = _serialize_result(result)

        assert serialized["ok"] is False
        assert serialized["error"] == "API down"


# ── Tests: _apply_resource_limits ────────────────────────────────


class TestApplyResourceLimits:
    """Test _apply_resource_limits() function."""

    @patch("plugins._subprocess_worker.platform.system", return_value="Windows")
    def test_noop_on_windows(self, mock_sys):
        """No-op on Windows — returns without error."""
        # Should not raise
        _apply_resource_limits(512)

    @patch("plugins._subprocess_worker.platform.system", return_value="Darwin")
    def test_noop_on_macos(self, mock_sys):
        """No-op on macOS — returns without error."""
        _apply_resource_limits(512)

    @patch("plugins._subprocess_worker.platform.system", return_value="Linux")
    def test_calls_setrlimit_on_linux(self, mock_sys):
        """On Linux, calls resource.setrlimit with correct byte limit."""
        mock_resource = MagicMock()
        mock_resource.RLIMIT_AS = 9  # Arbitrary constant value

        with patch.dict("sys.modules", {"resource": mock_resource}):
            # Re-import to pick up mocked module
            _apply_resource_limits(256)

        expected_bytes = 256 * 1024 * 1024
        mock_resource.setrlimit.assert_called_once_with(
            mock_resource.RLIMIT_AS, (expected_bytes, expected_bytes)
        )


# ── Tests: _write_error ─────────────────────────────────────────


class TestWriteError:
    """Test _write_error() function."""

    def test_writes_json_error_to_stdout(self):
        """Error message is written as JSON to stdout."""
        with patch("sys.stdout") as mock_stdout:
            mock_stdout.write = MagicMock()
            mock_stdout.flush = MagicMock()
            _write_error("something broke")

        written = mock_stdout.write.call_args[0][0]
        parsed = json.loads(written)
        assert parsed["ok"] is False
        assert parsed["error"] == "something broke"
        assert "traceback" not in parsed

    def test_includes_traceback_when_provided(self):
        """Traceback is included in JSON output when given."""
        with patch("sys.stdout") as mock_stdout:
            mock_stdout.write = MagicMock()
            mock_stdout.flush = MagicMock()
            _write_error("crash", tb="File x.py, line 1\nError")

        written = mock_stdout.write.call_args[0][0]
        parsed = json.loads(written)
        assert parsed["ok"] is False
        assert parsed["error"] == "crash"
        assert parsed["traceback"] == "File x.py, line 1\nError"


# ── Tests: main() ───────────────────────────────────────────────


class TestMain:
    """Test main() entry point function."""

    @staticmethod
    def _mock_asyncio_run_with_result(result=None, error=None):
        """Build a side effect that closes the passed coroutine before returning."""

        def _runner(coro):
            with suppress(RuntimeError):
                coro.close()
            if error is not None:
                raise error
            return result

        return _runner

    def test_empty_input_exits_with_1(self):
        """Empty stdin causes sys.exit(1)."""
        with (
            patch("sys.stdin") as mock_stdin,
            patch("sys.stdout") as mock_stdout,
            pytest.raises(SystemExit, match="1"),
        ):
            mock_stdin.read.return_value = ""
            mock_stdout.write = MagicMock()
            mock_stdout.flush = MagicMock()
            main()

    def test_whitespace_only_input_exits_with_1(self):
        """Whitespace-only stdin causes sys.exit(1)."""
        with (
            patch("sys.stdin") as mock_stdin,
            patch("sys.stdout") as mock_stdout,
            pytest.raises(SystemExit, match="1"),
        ):
            mock_stdin.read.return_value = "   \n  "
            mock_stdout.write = MagicMock()
            mock_stdout.flush = MagicMock()
            main()

    def test_invalid_json_exits_with_1(self):
        """Invalid JSON on stdin causes sys.exit(1)."""
        with (
            patch("sys.stdin") as mock_stdin,
            patch("sys.stdout") as mock_stdout,
            pytest.raises(SystemExit, match="1"),
        ):
            mock_stdin.read.return_value = "not json{{"
            mock_stdout.write = MagicMock()
            mock_stdout.flush = MagicMock()
            main()

        # Verify error JSON was written
        written = mock_stdout.write.call_args[0][0]
        parsed = json.loads(written)
        assert parsed["ok"] is False
        assert "Invalid JSON" in parsed["error"]

    def test_valid_request_runs_plugin(self):
        """Valid JSON request triggers _run_plugin and writes result to stdout."""
        request = {
            "plugin_module": "plugins.community.example_plugin",
            "plugin_class": "ThreatFoxPlugin",
            "observable": "8.8.8.8",
            "obs_type": "ip",
            "config": {},
            "env_vars": {},
            "memory_limit_mb": 512,
        }
        fake_output = {"ok": True, "result": {"source": "test", "ok": True}}

        with (
            patch("sys.stdin") as mock_stdin,
            patch("sys.stdout") as mock_stdout,
            patch("plugins._subprocess_worker._apply_resource_limits") as mock_limits,
            patch("plugins._subprocess_worker.asyncio.run") as mock_run,
        ):
            mock_stdin.read.return_value = json.dumps(request)
            mock_stdout.write = MagicMock()
            mock_stdout.flush = MagicMock()
            mock_run.side_effect = self._mock_asyncio_run_with_result(
                result=fake_output
            )
            main()

        # Resource limits applied
        mock_limits.assert_called_once_with(512)
        # asyncio.run was called with the coroutine
        mock_run.assert_called_once()
        # Result written to stdout
        written = mock_stdout.write.call_args[0][0]
        parsed = json.loads(written)
        assert parsed == fake_output

    def test_env_vars_are_set(self):
        """Environment variables from request are set in os.environ."""
        request = {
            "plugin_module": "some.module",
            "plugin_class": "SomePlugin",
            "observable": "1.2.3.4",
            "obs_type": "ip",
            "config": {},
            "env_vars": {"MY_KEY": "my_value"},
            "memory_limit_mb": 256,
        }

        with (
            patch("sys.stdin") as mock_stdin,
            patch("sys.stdout") as mock_stdout,
            patch("plugins._subprocess_worker._apply_resource_limits"),
            patch("plugins._subprocess_worker.asyncio.run") as mock_run,
            patch.dict(os.environ, {}, clear=False),
        ):
            mock_stdin.read.return_value = json.dumps(request)
            mock_stdout.write = MagicMock()
            mock_stdout.flush = MagicMock()
            mock_run.side_effect = self._mock_asyncio_run_with_result(
                result={"ok": True, "result": {}}
            )
            main()

            assert os.environ.get("MY_KEY") == "my_value"

    def test_plugin_exception_exits_with_1(self):
        """Exception during plugin execution writes error JSON and exits."""
        request = {
            "plugin_module": "some.module",
            "plugin_class": "SomePlugin",
            "observable": "1.2.3.4",
            "obs_type": "ip",
            "config": {},
            "env_vars": {},
            "memory_limit_mb": 512,
        }

        with (
            patch("sys.stdin") as mock_stdin,
            patch("sys.stdout") as mock_stdout,
            patch("plugins._subprocess_worker._apply_resource_limits"),
            patch("plugins._subprocess_worker.asyncio.run") as mock_run,
            pytest.raises(SystemExit, match="1"),
        ):
            mock_stdin.read.return_value = json.dumps(request)
            mock_stdout.write = MagicMock()
            mock_stdout.flush = MagicMock()
            mock_run.side_effect = self._mock_asyncio_run_with_result(
                error=ImportError("No module named 'some.module'")
            )
            main()

        written = mock_stdout.write.call_args[0][0]
        parsed = json.loads(written)
        assert parsed["ok"] is False
        assert "some.module" in parsed["error"]
        assert "traceback" in parsed


# ── Tests: _run_plugin ───────────────────────────────────────────


class TestRunPlugin:
    """Test _run_plugin() async function."""

    @pytest.mark.asyncio
    async def test_import_error_raises(self):
        """Non-existent module raises ImportError."""
        request = {
            "plugin_module": "nonexistent.module.path",
            "plugin_class": "FakePlugin",
            "observable": "8.8.8.8",
            "obs_type": "ip",
            "config": {},
        }
        with pytest.raises(ModuleNotFoundError):
            await _run_plugin(request)

    @pytest.mark.asyncio
    async def test_class_not_found_raises(self):
        """Valid module but missing class raises ImportError."""
        request = {
            "plugin_module": "plugins._subprocess_worker",  # valid module
            "plugin_class": "NonExistentClassName",
            "observable": "8.8.8.8",
            "obs_type": "ip",
            "config": {},
        }
        with pytest.raises(ImportError, match="Class 'NonExistentClassName' not found"):
            await _run_plugin(request)

    @pytest.mark.asyncio
    async def test_successful_plugin_run(self):
        """Successful plugin execution returns ok=True dict."""
        # Create a fake module with a fake plugin class
        fake_result = _FakePluginResult(
            source="fake_plugin",
            ok=True,
            raw_data={"data": "value"},
            evidence=[],
        )
        fake_plugin_instance = MagicMock()
        fake_plugin_instance.configure = MagicMock()
        fake_plugin_instance.query = AsyncMock(return_value=fake_result)

        fake_class = MagicMock(return_value=fake_plugin_instance)
        fake_module = MagicMock()
        fake_module.MyPlugin = fake_class

        request = {
            "plugin_module": "some.fake.module",
            "plugin_class": "MyPlugin",
            "observable": "1.2.3.4",
            "obs_type": "ip",
            "config": {"key": "value"},
        }

        with patch("plugins._subprocess_worker.importlib.import_module") as mock_import:
            mock_import.return_value = fake_module
            result = await _run_plugin(request)

        assert result["ok"] is True
        assert result["result"]["source"] == "fake_plugin"
        fake_plugin_instance.configure.assert_called_once_with({"key": "value"})
        fake_plugin_instance.query.assert_awaited_once_with("1.2.3.4", "ip")
