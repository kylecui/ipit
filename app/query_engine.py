"""
Query orchestration engine for threat intelligence analysis.

v2.0: Uses PluginRegistry to discover and run TI plugins instead of
the hardcoded CollectorAggregator. Each plugin handles collection,
normalization, AND scoring in a single self-contained unit.
"""

import asyncio
import logging
import os
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

import yaml

from models import Observable, ContextProfile, IPProfile, EvidenceItem, Verdict
from enrichers.semantic_enricher import SemanticEnricher
from analyzers.reputation_engine import ReputationEngine
from analyzers.verdict_engine import VerdictEngine
from analyzers.contextual_risk_engine import ContextualRiskEngine
from analyzers.noise_engine import NoiseEngine
from plugins import PluginRegistry, PluginResult, TIPlugin, SandboxedPluginRunner
from cache.cache_store import CacheStore

logger = logging.getLogger(__name__)

# ── Profile-level field mapping ────────────────────────────────────
# Keys that plugins may return in PluginResult.normalized_data
# and the corresponding IPProfile attribute to set.
_PROFILE_FIELD_MAP = {
    "organization": "organization",
    "country": "country",
    "asn": "asn",
    "network": "network",
    "rdns": "rdns",
    "hostnames": "hostnames",
}


def _load_plugin_config() -> dict[str, Any]:
    """Load plugins.yaml from config/plugins.yaml."""
    config_path = os.path.join(
        os.path.dirname(__file__), "..", "config", "plugins.yaml"
    )
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        logger.error(f"Failed to load plugin config: {e}")
        return {}


class QueryEngine:
    """Orchestrates the threat intelligence analysis pipeline.

    v2.0: Replaces CollectorAggregator with PluginRegistry.
    Plugins are auto-discovered from plugins/builtin/ and plugins/community/.
    """

    def __init__(self):
        self.semantic_enricher = SemanticEnricher()
        self.reputation_engine = ReputationEngine()
        self.verdict_engine = VerdictEngine()
        self.cache = CacheStore()
        self.contextual_risk_engine = ContextualRiskEngine()
        self.noise_engine = NoiseEngine()

        # v2.0 — Plugin system
        plugin_config = _load_plugin_config()
        self.registry = PluginRegistry(plugin_config)
        self.registry.discover()

        # v2.0 — Sandbox runner for untrusted plugins
        self._sandbox_runner = SandboxedPluginRunner()

    async def analyze(
        self,
        observable: Observable,
        context: Optional[ContextProfile] = None,
        refresh: bool = False,
    ) -> Verdict:
        """
        Main analysis pipeline.

        Flow:
        1. collect — run enabled plugins concurrently
        2. normalize — apply plugin normalized_data to profile
        3. enrich — add semantic tags
        4. analyze — reputation + contextual + noise analysis
        5. verdict — final decision with evidence fusion
        """

        if observable.type == "ip":
            profile, plugin_evidence = await self._collect_ip_data(
                observable.value, refresh=refresh
            )
            enriched_profile = await self._enrich_ip_profile(profile)
            verdict = await self._analyze_ip_profile(
                enriched_profile, plugin_evidence, context, refresh=refresh
            )
            return verdict

        elif observable.type == "domain":
            return Verdict(
                object_type="domain",
                object_value=observable.value,
                reputation_score=0,
                contextual_score=0,
                final_score=0,
                level="Inconclusive",
                confidence=0.0,
                decision="collect_more_context",
                summary="Domain analysis pipeline not implemented",
                evidence=[],
                tags=[],
            )

        elif observable.type == "url":
            return Verdict(
                object_type="url",
                object_value=observable.value,
                reputation_score=0,
                contextual_score=0,
                final_score=0,
                level="Inconclusive",
                confidence=0.0,
                decision="collect_more_context",
                summary="URL analysis pipeline not implemented",
                evidence=[],
                tags=[],
            )

        else:
            raise ValueError(f"Unsupported observable type: {observable.type}")

    # ── Collection via plugins ─────────────────────────────────────

    async def _collect_ip_data(
        self, ip: str, refresh: bool = False
    ) -> Tuple[IPProfile, List[EvidenceItem]]:
        """Collect IP data from all enabled plugins.

        Returns:
            Tuple of (IPProfile, plugin_evidence_list)
        """
        # Check cache first unless refresh is requested
        if not refresh:
            cached_profile = self.cache.get_normalized_profile(ip)
            if cached_profile:
                return cached_profile, []

        # Get enabled plugins for IP observable type
        plugins = self.registry.get_enabled("ip")
        logger.info(
            f"Running {len(plugins)} plugins for IP {ip}: "
            f"{[p.metadata.name for p in plugins]}"
        )

        # Run all plugins concurrently with fault-tolerance
        results = await asyncio.gather(
            *[self._safe_query(plugin, ip, "ip") for plugin in plugins]
        )

        # Convert PluginResults → legacy sources dict + collect evidence
        sources: Dict[str, Dict[str, Any]] = {}
        all_evidence: List[EvidenceItem] = []

        profile = IPProfile(ip=ip)

        for result in results:
            # Legacy format for backward compat with NoiseEngine,
            # narrative_reporter, and graph/correlator
            sources[result.source] = {
                "source": result.source,
                "ok": result.ok,
                "data": result.raw_data or {},
                "error": result.error,
            }

            # Collect evidence from plugins (pre-scored)
            all_evidence.extend(result.evidence)

            # Apply profile-level normalized data (organization, country, etc.)
            if result.ok and result.normalized_data:
                self._apply_profile_data(profile, result.normalized_data)

        profile.sources = sources
        profile.timestamps = {
            "normalized_at": datetime.now(),
            "collected_at": datetime.now(),
        }

        # Cache raw results and normalized profile
        self.cache.set_collector_results(ip, sources)
        self.cache.set_normalized_profile(ip, profile)

        return profile, all_evidence

    async def _safe_query(
        self, plugin: TIPlugin, observable: str, obs_type: str
    ) -> PluginResult:
        """Run a single plugin query with fault-tolerance.

        Sandboxed plugins (community/ by default) run in an isolated subprocess.
        Trusted plugins (builtin/ by default) run in-process for zero overhead.
        """
        plugin_name = plugin.metadata.name

        try:
            if self.registry.is_sandboxed(plugin_name):
                sandbox_config = self.registry.get_sandbox_config(plugin_name)
                logger.debug(
                    "Running plugin '%s' in sandbox (timeout=%ds)",
                    plugin_name,
                    sandbox_config.get("timeout", 30),
                )
                return await self._sandbox_runner.run(
                    plugin, observable, obs_type, sandbox_config
                )
            else:
                return await plugin.query(observable, obs_type)
        except Exception as e:
            logger.error(f"Plugin '{plugin_name}' crashed: {e}", exc_info=True)
            return PluginResult(
                source=plugin_name,
                ok=False,
                raw_data=None,
                normalized_data=None,
                evidence=[],
                error=f"Plugin crashed: {e}",
            )

    @staticmethod
    def _apply_profile_data(
        profile: IPProfile, normalized_data: Dict[str, Any]
    ) -> None:
        """Apply plugin normalized_data fields to the IPProfile.

        Only sets fields that are present in the plugin's output and
        haven't already been set by a higher-priority plugin.
        """
        for data_key, profile_attr in _PROFILE_FIELD_MAP.items():
            if data_key in normalized_data:
                current = getattr(profile, profile_attr, None)
                if current is None or (isinstance(current, list) and len(current) == 0):
                    setattr(profile, profile_attr, normalized_data[data_key])

    # ── Enrichment ─────────────────────────────────────────────────

    async def _enrich_ip_profile(self, profile: IPProfile) -> IPProfile:
        """Enrich IP profile with semantic information."""
        return self.semantic_enricher.enrich(profile)

    # ── Analysis ───────────────────────────────────────────────────

    async def _analyze_ip_profile(
        self,
        profile: IPProfile,
        plugin_evidence: List[EvidenceItem],
        context: Optional[ContextProfile] = None,
        refresh: bool = False,
    ) -> Verdict:
        """Analyze IP profile for threats.

        v2.0 change: Plugins already produced scored evidence. The
        ReputationEngine now only adds semantic tag adjustments.
        """
        # Check cache first unless refresh
        if not refresh:
            cached_verdict = self.cache.get_verdict(profile.ip)
            if cached_verdict:
                return cached_verdict

        # Get reputation score and evidence
        # v2.0: ReputationEngine still evaluates source-specific rules
        # from scoring_rules.yaml AND applies semantic adjustments.
        # Plugin evidence is merged in below.
        reputation_score, reputation_evidence = self.reputation_engine.analyze(
            profile, plugin_evidence=plugin_evidence
        )

        # Get contextual score and evidence
        contextual_adjustment, contextual_evidence = (
            self.contextual_risk_engine.analyze(profile, context)
        )
        contextual_score = contextual_adjustment

        # Get noise analysis
        noise_score, noise_classification, noise_evidence = self.noise_engine.analyze(
            profile
        )

        # Combine evidence: plugin + reputation + contextual + noise
        all_evidence = (
            plugin_evidence + reputation_evidence + contextual_evidence + noise_evidence
        )

        # Sum plugin evidence scores into reputation_score
        plugin_score = sum(e.score_delta for e in plugin_evidence)
        total_reputation_score = reputation_score + plugin_score

        # Generate verdict
        verdict = self.verdict_engine.generate_verdict(
            object_type="ip",
            object_value=profile.ip,
            reputation_score=total_reputation_score,
            contextual_score=contextual_score,
            evidence=all_evidence,
            tags=profile.tags,
            raw_sources=profile.sources,
        )

        # Cache verdict
        self.cache.set_verdict(profile.ip, verdict)

        return verdict
