"""
Reputation engine for analyzing threat intelligence data.
"""

import logging
from typing import List, Tuple
from ..models import IPProfile, EvidenceItem

logger = logging.getLogger(__name__)


class ReputationEngine:
    """Analyzes IP reputation from collected threat intelligence."""

    def analyze(self, profile: IPProfile) -> Tuple[int, List[EvidenceItem]]:
        """
        Analyze IP reputation and generate evidence.

        Args:
            profile: Normalized IP profile

        Returns:
            Tuple of (reputation_score, evidence_list)
        """
        score = 0
        evidence = []

        # Analyze each source
        sources = profile.sources or {}

        # AbuseIPDB analysis
        if "abuseipdb" in sources and sources["abuseipdb"]["ok"]:
            score_delta, abuse_evidence = self._analyze_abuseipdb(
                sources["abuseipdb"]["data"]
            )
            score += score_delta
            evidence.extend(abuse_evidence)

        # OTX analysis
        if "otx" in sources and sources["otx"]["ok"]:
            score_delta, otx_evidence = self._analyze_otx(sources["otx"]["data"])
            score += score_delta
            evidence.extend(otx_evidence)

        # GreyNoise analysis
        if "greynoise" in sources and sources["greynoise"]["ok"]:
            score_delta, gn_evidence = self._analyze_greynoise(
                sources["greynoise"]["data"]
            )
            score += score_delta
            evidence.extend(gn_evidence)

        # Apply semantic adjustments
        if profile.tags:
            score_delta, semantic_evidence = self._apply_semantic_adjustments(
                profile.tags
            )
            score += score_delta
            evidence.extend(semantic_evidence)

        # Clamp score to 0-100
        score = max(0, min(100, score))

        return score, evidence

    def _analyze_abuseipdb(self, data: dict) -> Tuple[int, List[EvidenceItem]]:
        """Analyze AbuseIPDB data."""
        score = 0
        evidence = []

        confidence = data.get("abuse_confidence_score", 0)

        if confidence >= 90:
            score += 30
            evidence.append(
                EvidenceItem(
                    source="abuseipdb",
                    category="reputation",
                    severity="high",
                    title="High abuse confidence",
                    detail=f"AbuseIPDB confidence score: {confidence}%",
                    score_delta=30,
                    confidence=confidence / 100.0,
                )
            )
        elif confidence >= 70:
            score += 20
            evidence.append(
                EvidenceItem(
                    source="abuseipdb",
                    category="reputation",
                    severity="medium",
                    title="Moderate abuse confidence",
                    detail=f"AbuseIPDB confidence score: {confidence}%",
                    score_delta=20,
                    confidence=confidence / 100.0,
                )
            )
        elif confidence > 0:
            score += 5  # Small positive for any reports
            evidence.append(
                EvidenceItem(
                    source="abuseipdb",
                    category="reputation",
                    severity="low",
                    title="Low abuse confidence",
                    detail=f"AbuseIPDB confidence score: {confidence}%",
                    score_delta=5,
                    confidence=confidence / 100.0,
                )
            )

        return score, evidence

    def _analyze_otx(self, data: dict) -> Tuple[int, List[EvidenceItem]]:
        """Analyze OTX data."""
        score = 0
        evidence = []

        pulse_count = data.get("pulse_count", 0)
        reputation = data.get("reputation", 0)

        if pulse_count > 0:
            # OTX pulses indicate malicious activity
            delta = min(20, pulse_count * 2)  # Cap at 20
            score += delta
            evidence.append(
                EvidenceItem(
                    source="otx",
                    category="reputation",
                    severity="medium",
                    title="OTX pulse activity",
                    detail=f"Found in {pulse_count} OTX pulses",
                    score_delta=delta,
                    confidence=min(0.8, pulse_count / 10.0),
                )
            )

        return score, evidence

    def _analyze_greynoise(self, data: dict) -> Tuple[int, List[EvidenceItem]]:
        """Analyze GreyNoise data."""
        score = 0
        evidence = []

        classification = data.get("classification", "").lower()
        noise = data.get("noise", False)
        riot = data.get("riot", False)

        if classification == "malicious":
            score += 20
            evidence.append(
                EvidenceItem(
                    source="greynoise",
                    category="reputation",
                    severity="high",
                    title="GreyNoise malicious classification",
                    detail="IP classified as malicious by GreyNoise",
                    score_delta=20,
                    confidence=0.9,
                )
            )
        elif noise or riot:
            score -= 15  # Reduce score for benign noise/riot
            evidence.append(
                EvidenceItem(
                    source="greynoise",
                    category="reputation",
                    severity="low",
                    title="GreyNoise benign activity",
                    detail=f"IP classified as {'noise' if noise else 'riot'} - benign background activity",
                    score_delta=-15,
                    confidence=0.8,
                )
            )

        return score, evidence

    def _apply_semantic_adjustments(
        self, tags: List[str]
    ) -> Tuple[int, List[EvidenceItem]]:
        """Apply score adjustments based on semantic tags."""
        score = 0
        evidence = []

        adjustments = {
            "cloud_provider": -15,
            "microsoft_service": -25,
            "google_service": -25,
            "official_service": -25,
            "shared_infrastructure": -10,
        }

        for tag in tags:
            if tag in adjustments:
                delta = adjustments[tag]
                score += delta
                evidence.append(
                    EvidenceItem(
                        source="semantic",
                        category="adjustment",
                        severity="low",
                        title=f"Semantic adjustment: {tag}",
                        detail=f"IP identified as {tag.replace('_', ' ')}, reducing suspicion",
                        score_delta=delta,
                        confidence=0.9,
                    )
                )

        return score, evidence
