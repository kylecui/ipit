"""
Plugin registry for TIRE v2.0 — discovers, registers, and manages TI plugins.
"""

import importlib
import inspect
import logging
import os
from pathlib import Path
from typing import Any

from plugins.base import TIPlugin, PluginMetadata

logger = logging.getLogger(__name__)


class PluginRegistry:
    """Discovers, registers, and manages TI plugins."""

    def __init__(self, config: dict[str, Any]) -> None:
        self._plugins: dict[str, TIPlugin] = {}
        self._config = config  # loaded from plugins.yaml

    def discover(self, plugin_dirs: list[str] | None = None) -> None:
        """Auto-discover plugins by scanning directories for TIPlugin subclasses.

        Default scan paths:
            - plugins/builtin/
            - plugins/community/
        """
        dirs = plugin_dirs or ["plugins/builtin", "plugins/community"]

        for plugin_dir in dirs:
            if not os.path.isdir(plugin_dir):
                logger.debug(f"Plugin directory not found, skipping: {plugin_dir}")
                continue

            for file in sorted(Path(plugin_dir).glob("*.py")):
                if file.name.startswith("_"):
                    continue

                # Convert file path to module path
                # e.g. plugins/builtin/abuseipdb.py -> plugins.builtin.abuseipdb
                module_path = str(file).replace(os.sep, ".").removesuffix(".py")

                try:
                    module = importlib.import_module(module_path)
                    for _, obj in inspect.getmembers(module, inspect.isclass):
                        if (
                            issubclass(obj, TIPlugin)
                            and obj is not TIPlugin
                            and not inspect.isabstract(obj)
                        ):
                            plugin = obj()
                            self.register(plugin)
                except Exception as e:
                    logger.error(f"Failed to load plugin from {file}: {e}")

    def register(self, plugin: TIPlugin) -> None:
        """Register a plugin after validating its contract."""
        meta = plugin.metadata
        name = meta.name

        # Validate contract
        if not meta.name or not meta.supported_types:
            raise ValueError(
                f"Plugin '{name}' has invalid metadata: "
                f"name and supported_types are required"
            )

        # Check config — skip disabled plugins
        plugin_config = self._config.get("plugins", {}).get(name, {})
        if not plugin_config.get("enabled", True):
            logger.info(f"Plugin '{name}' is disabled in config — skipping")
            return

        # Apply config
        plugin.configure(plugin_config.get("config", {}))
        plugin.on_register()

        self._plugins[name] = plugin
        logger.info(f"Registered plugin: {meta.display_name} v{meta.version}")

    def get_enabled(self, obs_type: str) -> list[TIPlugin]:
        """Get all enabled plugins that support the given observable type,
        sorted by priority (lower = first)."""
        plugins = [
            p for p in self._plugins.values() if obs_type in p.metadata.supported_types
        ]
        return sorted(plugins, key=lambda p: p.metadata.priority)

    def get_by_name(self, name: str) -> TIPlugin | None:
        """Get a specific plugin by name."""
        return self._plugins.get(name)

    def list_all(self) -> list[PluginMetadata]:
        """List metadata for all registered plugins."""
        return [p.metadata for p in self._plugins.values()]
