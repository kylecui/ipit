"""
Verdict engine for final risk assessment and decision making.
"""

import logging
from typing import List
from ..models import Verdict, EvidenceItem

logger = logging.getLogger(__name__)


class VerdictEngine:
    """Generates final verdicts from analysis results."""

    # Score thresholds for verdict levels
    SCORE_THRESHOLDS = {
        "Low": (0, 20),
        "Medium": (21, 45),
        "High": (46, 75),
        "Critical": (76, 100),
    }

    # Decision mappings
    DECISIONS = {
        "Low": "allow_with_monitoring",
        "Medium": "investigate",
        "High": "alert_and_review",
        "Critical": "contain_or_block",
        "Inconclusive": "collect_more_context",
    }

    def generate_verdict(
        self,
        object_type: str,
        object_value: str,
        reputation_score: int,
        contextual_score: int,
        evidence: List[EvidenceItem],
        tags: List[str] = None,
    ) -> Verdict:
        """
        Generate final verdict from analysis results.

        Args:
            object_type: Type of object (ip, domain, etc.)
            object_value: The object value
            reputation_score: Score from reputation analysis
            contextual_score: Score from contextual analysis
            evidence: List of evidence items
            tags: Semantic tags

        Returns:
            Final Verdict
        """
        # Calculate final score
        final_score = reputation_score + contextual_score
        final_score = max(0, min(100, final_score))  # Clamp to 0-100

        # Determine level
        level = self._determine_level(final_score, evidence)

        # Get decision
        decision = self.DECISIONS.get(level, "investigate")

        # Calculate confidence
        confidence = self._calculate_confidence(evidence, final_score)

        # Generate summary
        summary = self._generate_summary(
            object_type, object_value, level, final_score, evidence
        )

        return Verdict(
            object_type=object_type,
            object_value=object_value,
            reputation_score=reputation_score,
            contextual_score=contextual_score,
            final_score=final_score,
            level=level,
            confidence=confidence,
            decision=decision,
            summary=summary,
            evidence=evidence,
            tags=tags or [],
        )

    def _determine_level(self, final_score: int, evidence: List[EvidenceItem]) -> str:
        """Determine verdict level based on score and evidence."""
        # Check for inconclusive conditions
        if self._should_be_inconclusive(evidence):
            return "Inconclusive"

        # Determine level by score
        for level, (min_score, max_score) in self.SCORE_THRESHOLDS.items():
            if min_score <= final_score <= max_score:
                return level

        # Fallback
        return "Medium"

    def _should_be_inconclusive(self, evidence: List[EvidenceItem]) -> bool:
        """Check if verdict should be inconclusive based on evidence conflicts."""
        # Simple heuristic: if we have conflicting evidence, be inconclusive
        positive_evidence = [e for e in evidence if e.score_delta > 0]
        negative_evidence = [e for e in evidence if e.score_delta < 0]

        # If we have both positive and negative evidence, it might be inconclusive
        if positive_evidence and negative_evidence:
            # Check if the evidence is truly conflicting
            has_strong_positive = any(e.score_delta >= 20 for e in positive_evidence)
            has_strong_negative = any(e.score_delta <= -15 for e in negative_evidence)

            if has_strong_positive and has_strong_negative:
                return True

        return False

    def _calculate_confidence(
        self, evidence: List[EvidenceItem], final_score: int
    ) -> float:
        """Calculate confidence in the verdict."""
        if not evidence:
            return 0.0

        # Base confidence on evidence strength and consistency
        total_confidence = sum(e.confidence for e in evidence if e.confidence > 0)
        avg_confidence = total_confidence / len(evidence) if evidence else 0.0

        # Adjust based on score magnitude
        score_factor = min(
            1.0, final_score / 50.0
        )  # Higher scores give higher confidence

        return min(1.0, (avg_confidence + score_factor) / 2.0)

    def _generate_summary(
        self,
        object_type: str,
        object_value: str,
        level: str,
        final_score: int,
        evidence: List[EvidenceItem],
    ) -> str:
        """Generate human-readable summary."""
        summaries = {
            "Low": f"{object_type.upper()} {object_value} shows minimal threat indicators. "
            f"Final score: {final_score}/100. Safe for normal operations with monitoring.",
            "Medium": f"{object_type.upper()} {object_value} has moderate threat indicators. "
            f"Final score: {final_score}/100. Recommend investigation before allowing.",
            "High": f"{object_type.upper()} {object_value} shows significant malicious activity. "
            f"Final score: {final_score}/100. Alert and review required.",
            "Critical": f"{object_type.upper()} {object_value} shows critical threat indicators. "
            f"Final score: {final_score}/100. Immediate containment recommended.",
            "Inconclusive": f"{object_type.upper()} {object_value} has conflicting evidence. "
            f"Final score: {final_score}/100. More context needed for accurate assessment.",
        }

        return summaries.get(
            level,
            f"Analysis complete for {object_type} {object_value}. "
            f"Verdict: {level}, Score: {final_score}/100.",
        )
