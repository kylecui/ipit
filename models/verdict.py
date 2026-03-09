"""
Verdict model for final analysis results.
"""

from pydantic import BaseModel
from typing import List, Optional
from .evidence import EvidenceItem


class Verdict(BaseModel):
    """Final verdict from threat intelligence analysis."""

    object_type: str
    object_value: str
    reputation_score: int
    contextual_score: int
    final_score: int
    level: str
    confidence: float
    decision: str
    summary: str
    evidence: List[EvidenceItem] = []
    tags: List[str] = []
