"""
TIRE v2.0 Plugin System.
"""

from plugins.base import TIPlugin, PluginMetadata, PluginResult
from plugins.registry import PluginRegistry

__all__ = [
    "TIPlugin",
    "PluginMetadata",
    "PluginResult",
    "PluginRegistry",
]
