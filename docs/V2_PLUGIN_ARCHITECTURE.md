# TIRE v2.0 — Plugin Architecture Design

## 1. Executive Summary

**Current state (v1.0):** TIRE has 9 hardcoded threat intelligence collectors. Adding a new source requires changes in 3–5 files: the collector module, the `collectors/__init__.py` aggregator, the normalizer (if the source provides profile-level data), the `reputation_engine.py` (if the source contributes to scoring), and `scoring_rules.yaml`. This is the classic "shotgun surgery" code smell.

**Target state (v2.0):** TIRE becomes a **platform** where every intelligence source is a self-contained plugin. Adding a new source means dropping a single Python file into `plugins/` and adding a YAML config entry. Zero changes to core platform code.

**Key benefit:** Security teams can integrate new TI feeds, internal APIs, or commercial services without understanding or modifying the core engine.

---

## 2. Current Architecture Analysis

### 2.1 Coupling Points

The following files must be modified to add a single new intelligence source:

| File | What's hardcoded | Why it's a problem |
|------|------------------|--------------------|
| `collectors/__init__.py` | Imports + `_initialize_collectors()` list (lines 9–17, 30–40) | Every new collector requires a new import and list entry |
| `normalizers/ip_normalizer.py` | `if "rdap" in collected_data` / `if "reverse_dns" in collected_data` (lines 32–38) | Normalizer knows source names; new sources that provide profile-level data need new branches |
| `analyzers/reputation_engine.py` | 6 repeated `if "source_name" in self.scoring_rules` blocks (lines 54–94) | Each source is a copy-pasted block; adding a source means adding another block |
| `rules/scoring_rules.yaml` | `sources.abuseipdb`, `sources.otx`, etc. | Scoring rules reference sources by name (this is acceptable — it's configuration) |
| `app/config.py` | `abuseipdb_api_key`, `otx_api_key`, etc. (lines 14–18) | API keys are hardcoded as Settings fields; new sources need new fields |

### 2.2 The "Shotgun Surgery" Problem

Adding a hypothetical "ThreatFox" source today requires:

1. Create `collectors/threatfox.py` (new file — fine)
2. Edit `collectors/__init__.py` — add import + add to list
3. Edit `app/config.py` — add `threatfox_api_key` field
4. Edit `rules/scoring_rules.yaml` — add `sources.threatfox` rules
5. Edit `analyzers/reputation_engine.py` — add another `if "threatfox"` block
6. Optionally edit `normalizers/ip_normalizer.py` if ThreatFox provides profile data

Steps 2, 3, and 5 are pure boilerplate that can be eliminated with a plugin system.

### 2.3 What Already Works Well

- **BaseCollector ABC** — clean interface: `async def query(observable) -> {source, ok, data, error}`
- **CollectorAggregator** — concurrent execution with fault isolation
- **VerdictEngine** — already source-agnostic, works on `EvidenceItem` lists
- **Reporters** — fully decoupled, work on `Verdict` objects
- **YAML scoring rules** — declarative, already externalized

These are preserved in v2.0.

---

## 3. Plugin System Design

### 3.1 Plugin Interface

Each plugin is **self-contained** — it handles collection, normalization, AND scoring for its source. This eliminates cross-module coupling entirely.

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any
from models import EvidenceItem


@dataclass
class PluginMetadata:
    name: str                       # "virustotal" — unique identifier
    display_name: str               # "VirusTotal" — human-readable
    version: str                    # "1.0.0" — semver
    supported_types: list[str]      # ["ip", "domain", "url", "hash"]
    requires_api_key: bool          # True
    api_key_env_var: str | None     # "VT_API_KEY"
    rate_limit: float | None        # requests per second, or None
    priority: int                   # lower = runs first (default 50)
    tags: list[str]                 # ["reputation", "malware", "passive_dns"]
    description: str                # one-liner


@dataclass
class PluginResult:
    source: str                     # plugin name
    ok: bool
    raw_data: dict | None           # raw API response
    normalized_data: dict | None    # standardized fields
    evidence: list[EvidenceItem]    # scored evidence items
    error: str | None


class TIPlugin(ABC):
    """Base class for all Threat Intelligence plugins."""

    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        ...

    @abstractmethod
    async def query(self, observable: str, obs_type: str) -> PluginResult:
        """
        Execute the full plugin pipeline:
        1. Call external API
        2. Normalize raw response
        3. Score and generate evidence

        Args:
            observable: The value to query (IP, domain, etc.)
            obs_type: The observable type ("ip", "domain", "url", "hash")

        Returns:
            PluginResult with raw data, normalized data, and evidence items
        """
        ...

    def configure(self, config: dict[str, Any]) -> None:
        """
        Receive plugin-specific configuration from plugins.yaml.
        Called once at registration time. Override if needed.
        """
        self.plugin_config = config

    def on_register(self) -> None:
        """Lifecycle hook: called when plugin is registered. Override if needed."""
        pass

    def on_enable(self) -> None:
        """Lifecycle hook: called when plugin is enabled. Override if needed."""
        pass

    def on_disable(self) -> None:
        """Lifecycle hook: called when plugin is disabled. Override if needed."""
        pass
```

**Key design decision:** The `query()` method returns a `PluginResult` that contains raw data, normalized data, AND evidence — all produced by the plugin itself. The core platform never needs to know how to interpret source-specific data.

### 3.2 Plugin Registry

```python
import importlib
import inspect
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


class PluginRegistry:
    """Discovers, registers, and manages TI plugins."""

    def __init__(self, config: dict):
        self._plugins: dict[str, TIPlugin] = {}
        self._config = config  # loaded from plugins.yaml

    def discover(self, plugin_dirs: list[str] = None) -> None:
        """
        Auto-discover plugins by scanning directories for TIPlugin subclasses.

        Default scan paths:
        - plugins/builtin/
        - plugins/community/
        """
        dirs = plugin_dirs or ["plugins/builtin", "plugins/community"]

        for plugin_dir in dirs:
            if not os.path.isdir(plugin_dir):
                continue

            for file in Path(plugin_dir).glob("*.py"):
                if file.name.startswith("_"):
                    continue
                module_path = str(file).replace(os.sep, ".").removesuffix(".py")
                try:
                    module = importlib.import_module(module_path)
                    for _, obj in inspect.getmembers(module, inspect.isclass):
                        if issubclass(obj, TIPlugin) and obj is not TIPlugin:
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
            raise ValueError(f"Plugin {name} has invalid metadata")

        # Apply config
        plugin_config = self._config.get("plugins", {}).get(name, {})
        if not plugin_config.get("enabled", True):
            logger.info(f"Plugin '{name}' is disabled in config — skipping")
            return

        plugin.configure(plugin_config.get("config", {}))
        plugin.on_register()

        self._plugins[name] = plugin
        logger.info(f"Registered plugin: {meta.display_name} v{meta.version}")

    def get_enabled(self, obs_type: str) -> list[TIPlugin]:
        """Get all enabled plugins that support the given observable type, sorted by priority."""
        plugins = [
            p for p in self._plugins.values()
            if obs_type in p.metadata.supported_types
        ]
        return sorted(plugins, key=lambda p: p.metadata.priority)

    def get_by_name(self, name: str) -> TIPlugin | None:
        """Get a specific plugin by name."""
        return self._plugins.get(name)

    def list_all(self) -> list[PluginMetadata]:
        """List metadata for all registered plugins."""
        return [p.metadata for p in self._plugins.values()]
```

### 3.3 Plugin Configuration

Per-plugin configuration via YAML, replacing hardcoded `Settings` fields:

```yaml
# config/plugins.yaml

plugins:
  abuseipdb:
    enabled: true
    api_key_env: ABUSEIPDB_API_KEY
    priority: 10
    config:
      max_age_days: 90
      min_confidence: 25

  virustotal:
    enabled: true
    api_key_env: VT_API_KEY
    priority: 10
    config:
      include_passive_dns: true
      max_resolutions: 50

  otx:
    enabled: true
    api_key_env: OTX_API_KEY
    priority: 20
    config: {}

  greynoise:
    enabled: true
    api_key_env: GREYNOISE_API_KEY
    priority: 20
    config: {}

  shodan:
    enabled: true
    api_key_env: SHODAN_API_KEY
    priority: 30
    config: {}

  rdap:
    enabled: true
    api_key_env: null
    priority: 5
    config: {}

  reverse_dns:
    enabled: true
    api_key_env: null
    priority: 5
    config: {}

  honeynet:
    enabled: true
    api_key_env: null
    priority: 40
    config: {}

  internal_flow:
    enabled: true
    api_key_env: null
    priority: 40
    config: {}

  # Example: adding a new source requires only this entry + a plugin file
  # threatfox:
  #   enabled: true
  #   api_key_env: null
  #   priority: 50
  #   config:
  #     max_results: 100
```

API keys are resolved at runtime: the plugin reads `os.environ.get(self.metadata.api_key_env_var)`. This eliminates the need for hardcoded `Settings` fields per source.

### 3.4 Modified Pipeline

```
                    v1.0 (current)                      v2.0 (target)
                    ──────────────                      ─────────────
Input               CLI / API / Web                     CLI / API / Web (unchanged)
    ↓                                                       ↓
Orchestration       QueryEngine                         QueryEngine (simplified)
    ↓                                                       ↓
Collection          CollectorAggregator                 PluginRegistry.get_enabled(obs_type)
                    → 9 hardcoded collectors             → N dynamic plugins
    ↓                                                       ↓
Normalization       IPNormalizer (source-aware)          Plugin.query() returns normalized
    ↓                                                   data + evidence (self-contained)
Enrichment          SemanticEnricher                         ↓
    ↓                                                   SemanticEnricher (unchanged)
Analysis            ReputationEngine (source-aware)          ↓
                    → 6 hardcoded if-blocks             Evidence aggregation (generic)
    ↓                                                       ↓
Verdict             VerdictEngine                        VerdictEngine (unchanged)
    ↓                                                       ↓
Output              Reporters                            Reporters (unchanged)
```

**What changes:**
- `CollectorAggregator` → replaced by `PluginRegistry` + concurrent `plugin.query()` calls
- `IPNormalizer` source-specific branches → eliminated (plugins normalize their own data)
- `ReputationEngine` source-specific if-blocks → eliminated (plugins score their own data)
- `app/config.py` per-source API key fields → eliminated (plugins read env vars directly)

**What does NOT change:**
- `VerdictEngine` — already works on generic `EvidenceItem` lists
- `SemanticEnricher` — works on `IPProfile` tags, source-agnostic
- All `Reporters` — work on `Verdict` objects
- `ContextualRiskEngine`, `NoiseEngine` — work on profile data, not source names

### 3.5 Modified QueryEngine

```python
class QueryEngine:
    def __init__(self):
        self.plugin_registry = PluginRegistry(config=load_plugins_yaml())
        self.plugin_registry.discover()
        self.semantic_enricher = SemanticEnricher()
        self.verdict_engine = VerdictEngine()
        self.cache = CacheStore()

    async def _collect_ip_data(self, ip: str) -> tuple[IPProfile, list[EvidenceItem]]:
        plugins = self.plugin_registry.get_enabled("ip")

        # Run all plugins concurrently
        tasks = [self._safe_query(p, ip, "ip") for p in plugins]
        results: list[PluginResult] = await asyncio.gather(*tasks)

        # Aggregate
        all_evidence = []
        sources = {}
        for result in results:
            sources[result.source] = {
                "ok": result.ok,
                "data": result.raw_data,
                "error": result.error,
            }
            all_evidence.extend(result.evidence)

            # Apply profile-level data if plugin provides it
            # (e.g., RDAP provides org/asn/country)
            if result.normalized_data:
                self._apply_profile_data(profile, result.normalized_data)

        profile = IPProfile(ip=ip, sources=sources)
        return profile, all_evidence
```

---

## 4. Migration Path (v1.0 → v2.0)

### Phase 1: Plugin Abstraction (non-breaking)

1. Create `plugins/base.py` with `TIPlugin`, `PluginMetadata`, `PluginResult`
2. Create `plugins/registry.py` with `PluginRegistry`
3. Create `config/plugins.yaml`
4. Migrate existing 9 collectors to TIPlugin interface:
   - Each plugin file moves from `collectors/abuseipdb.py` → `plugins/builtin/abuseipdb.py`
   - Each plugin absorbs its own normalization logic (currently in `ip_normalizer.py`)
   - Each plugin absorbs its own scoring logic (currently split between `reputation_engine.py` and `scoring_rules.yaml`)
   - Scoring rules from YAML are loaded by each plugin, or embedded as plugin constants

**Migration per collector:**
```
collectors/abuseipdb.py          →  plugins/builtin/abuseipdb.py
  + scoring from reputation_engine.py lines 54-59
  + rules from scoring_rules.yaml sources.abuseipdb
  = self-contained AbuseIPDBPlugin
```

### Phase 2: Decouple Core

5. Replace `CollectorAggregator` usage in `QueryEngine` with `PluginRegistry`
6. Simplify `IPNormalizer` — remove source-specific branches (lines 32–38), keep only generic timestamp/metadata logic
7. Simplify `ReputationEngine` — remove 6 source-specific if-blocks (lines 54–94), replace with generic evidence aggregation from plugin results
8. Remove per-source API key fields from `app/config.py` — plugins read env vars directly

### Phase 3: Plugin Ecosystem (future)

9. `tire plugin scaffold <name>` — CLI command to generate plugin boilerplate
10. `tire plugin validate <path>` — validate plugin contract compliance
11. `tire plugin list` — show registered plugins and their status
12. Consider hot-reload (watch `plugins/` directory) — v2.1+

---

## 5. Example: Writing a New Plugin

A complete example of adding ThreatFox (abuse.ch) as a new plugin:

### Step 1: Create the plugin file

```python
# plugins/community/threatfox.py

import os
import httpx
from plugins.base import TIPlugin, PluginMetadata, PluginResult
from models import EvidenceItem


class ThreatFoxPlugin(TIPlugin):

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="threatfox",
            display_name="ThreatFox (abuse.ch)",
            version="1.0.0",
            supported_types=["ip", "domain", "url"],
            requires_api_key=False,
            api_key_env_var=None,
            rate_limit=1.0,  # 1 req/sec
            priority=50,
            tags=["ioc", "malware", "c2"],
            description="IOC database by abuse.ch — malware C2, botnet IPs",
        )

    async def query(self, observable: str, obs_type: str) -> PluginResult:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    "https://threatfox-api.abuse.ch/api/v1/",
                    json={"query": "search_ioc", "search_term": observable},
                )
                resp.raise_for_status()
                raw = resp.json()

            normalized = self._normalize(raw)
            evidence = self._score(normalized)

            return PluginResult(
                source=self.metadata.name,
                ok=True,
                raw_data=raw,
                normalized_data=normalized,
                evidence=evidence,
                error=None,
            )

        except Exception as e:
            return PluginResult(
                source=self.metadata.name,
                ok=False,
                raw_data=None,
                normalized_data=None,
                evidence=[],
                error=str(e),
            )

    def _normalize(self, raw: dict) -> dict:
        """Extract structured fields from ThreatFox response."""
        data = raw.get("data", [])
        if not data:
            return {"match_count": 0, "malware_families": [], "threat_types": []}

        families = list({entry.get("malware", "unknown") for entry in data})
        threat_types = list({entry.get("threat_type", "unknown") for entry in data})

        return {
            "match_count": len(data),
            "malware_families": families,
            "threat_types": threat_types,
            "first_seen": data[0].get("first_seen_utc"),
            "last_seen": data[0].get("last_seen_utc"),
            "confidence_level": data[0].get("confidence_level", 0),
        }

    def _score(self, normalized: dict) -> list[EvidenceItem]:
        """Generate evidence items from normalized data."""
        evidence = []
        count = normalized.get("match_count", 0)

        if count == 0:
            return evidence

        families = ", ".join(normalized.get("malware_families", []))
        severity = "critical" if count >= 3 else "high" if count >= 1 else "low"
        score = min(40, count * 15)

        evidence.append(
            EvidenceItem(
                source="threatfox",
                category="reputation",
                severity=severity,
                title="ThreatFox IOC match",
                detail=f"Found {count} IOC matches. Malware families: {families}",
                score_delta=score,
                confidence=normalized.get("confidence_level", 50) / 100,
            )
        )

        return evidence
```

### Step 2: Add config entry

```yaml
# config/plugins.yaml (append)
  threatfox:
    enabled: true
    api_key_env: null
    priority: 50
    config:
      max_results: 100
```

### Step 3: Done

No other files touched. The `PluginRegistry` auto-discovers `ThreatFoxPlugin` from `plugins/community/`, calls `configure()`, and includes it in concurrent queries. Evidence flows into `VerdictEngine` like any other source.

---

## 6. Technical Decisions

### Why self-contained plugins (collect + normalize + score)?

In v1.0, normalization and scoring are separated from collection. This creates coupling:

- `ip_normalizer.py` must know that RDAP provides `organization` and `country`
- `reputation_engine.py` must know that AbuseIPDB has `abuse_confidence_score`

By making each plugin responsible for its own normalization and scoring, we follow the **Information Expert** principle: the plugin that calls the API knows best how to interpret the response. No other module needs to understand source-specific data structures.

### Why filesystem discovery over stevedore/entry_points?

- TIRE is an internal tool, not a library ecosystem
- Filesystem discovery (`importlib` + `__subclasses__()`) works with zero additional dependencies
- No pip packaging overhead — just drop a `.py` file
- If TIRE ever needs distributable plugins (pip-installable), `entry_points` or `stevedore` can be added as an alternative discovery mechanism alongside filesystem scanning

### Why YAML config over database?

- Matches the existing pattern (`scoring_rules.yaml`, `action_rules.yaml`)
- Version-controllable in git
- No migration scripts needed
- Editable by security analysts without database access
- Environment-specific overrides via env vars remain possible

### Plugin error isolation

Each `plugin.query()` is wrapped in `try/except` by the orchestrator (same pattern as v1.0's `CollectorAggregator._safe_collect`). A failing plugin:
- Returns `PluginResult(ok=False, error=...)`
- Does not affect other plugins
- Is logged and included in debug output
- Contributes zero evidence (graceful degradation)

### Rate limiting

Each plugin declares its rate limit in `PluginMetadata.rate_limit` (requests per second). The registry enforces this via a per-plugin `asyncio.Semaphore` or token bucket. Plugins that don't declare a rate limit run without throttling.

### Testing

Each plugin is testable in isolation:

```python
# tests/plugins/test_threatfox.py

async def test_threatfox_malicious_ip():
    plugin = ThreatFoxPlugin()
    # Mock httpx response
    with respx.mock:
        respx.post("https://threatfox-api.abuse.ch/api/v1/").respond(
            json={"data": [{"malware": "Cobalt Strike", "threat_type": "c2", ...}]}
        )
        result = await plugin.query("1.2.3.4", "ip")

    assert result.ok
    assert len(result.evidence) == 1
    assert result.evidence[0].source == "threatfox"
    assert result.evidence[0].score_delta > 0
```

No need to spin up the full pipeline. Plugin tests are fast and focused.

---

## 7. File Structure (v2.0)

```
├── app/                            # Core platform
│   ├── api.py                      # FastAPI routes (unchanged)
│   ├── main.py                     # CLI entry point (unchanged)
│   ├── config.py                   # Simplified — no per-source API keys
│   ├── i18n.py                     # Unchanged
│   ├── query_engine.py             # Uses PluginRegistry instead of CollectorAggregator
│   └── llm_client.py               # Unchanged
├── plugins/                        # NEW — plugin system
│   ├── __init__.py
│   ├── base.py                     # TIPlugin ABC, PluginMetadata, PluginResult
│   ├── registry.py                 # PluginRegistry — discovery + management
│   ├── builtin/                    # Migrated v1.0 collectors (self-contained)
│   │   ├── __init__.py
│   │   ├── abuseipdb.py
│   │   ├── otx.py
│   │   ├── greynoise.py
│   │   ├── virustotal.py
│   │   ├── shodan.py
│   │   ├── rdap.py
│   │   ├── reverse_dns.py
│   │   ├── honeynet.py
│   │   └── internal_flow.py
│   └── community/                  # User-added plugins
│       ├── __init__.py
│       └── (drop new plugins here)
├── config/
│   └── plugins.yaml                # Per-plugin configuration
├── collectors/                     # DEPRECATED — kept during migration only
├── normalizers/                    # Simplified — generic profile assembly only
├── enrichers/                      # Unchanged
├── analyzers/
│   ├── reputation_engine.py        # Simplified — generic evidence aggregation
│   ├── verdict_engine.py           # Unchanged
│   ├── contextual_risk_engine.py   # Unchanged
│   └── noise_engine.py             # Unchanged
├── reporters/                      # Unchanged
├── models/                         # Add PluginResult if not in plugins/base.py
├── rules/                          # Unchanged (semantic_adjustments stay here)
├── templates/                      # Unchanged
├── locales/                        # Unchanged
├── docker-compose.yml
├── Dockerfile                      # Add COPY plugins/ and COPY config/
└── requirements.txt
```

---

## 8. Non-Goals (Explicitly Out of Scope for v2.0)

- **Plugin marketplace / remote installation** — plugins are local files, not downloaded packages
- **Plugin sandboxing / security isolation** — plugins run in the same process with full trust
- **Multi-language plugin support** — Python only
- **Hot-reload** — adding/removing plugins requires a restart (hot-reload is a v2.1+ consideration)
- **Breaking API contract** — v2.0 REST API responses remain backward-compatible with v1.0
- **Observable type expansion** — v2.0 focuses on the plugin architecture, not adding domain/URL/hash analysis pipelines (though the plugin interface supports them)
