"""
Unit tests for core models.
"""

import pytest
import sys
import os
from datetime import datetime

# Add the parent directory to sys.path to enable imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models import (
    Observable,
    IPProfile,
    DomainProfile,
    ContextProfile,
    EvidenceItem,
    Verdict,
)


class TestObservable:
    """Test Observable model."""

    def test_valid_observable(self):
        """Test valid observable creation."""
        obs = Observable(type="ip", value="8.8.8.8")
        assert obs.type == "ip"
        assert obs.value == "8.8.8.8"

    def test_invalid_type(self):
        """Test invalid observable type raises error."""
        with pytest.raises(ValueError):
            Observable(type="invalid", value="test")


class TestIPProfile:
    """Test IPProfile model."""

    def test_basic_ip_profile(self):
        """Test basic IP profile creation."""
        profile = IPProfile(ip="8.8.8.8")
        assert profile.ip == "8.8.8.8"
        assert profile.version == 4
        assert profile.rdns == []
        assert profile.tags == []
        assert profile.sources == {}

    def test_full_ip_profile(self):
        """Test full IP profile with all fields."""
        profile = IPProfile(
            ip="8.8.8.8",
            version=4,
            asn="AS15169",
            organization="Google LLC",
            country="US",
            network="8.8.8.0/24",
            rdns=["dns.google"],
            hostnames=["dns.google"],
            tags=["cloud_provider", "google_service"],
            sources={"rdap": {"asn": "AS15169"}},
            external_refs={},
            timestamps={"collected_at": datetime.now()},
        )
        assert profile.asn == "AS15169"
        assert profile.organization == "Google LLC"
        assert "cloud_provider" in profile.tags


class TestDomainProfile:
    """Test DomainProfile model."""

    def test_basic_domain_profile(self):
        """Test basic domain profile creation."""
        profile = DomainProfile(domain="example.com")
        assert profile.domain == "example.com"
        assert profile.tags == []
        assert profile.sources == {}


class TestContextProfile:
    """Test ContextProfile model."""

    def test_context_profile(self):
        """Test context profile creation."""
        context = ContextProfile(
            direction="outbound",
            protocol="tcp",
            port=443,
            hostname="example.com",
            process_name="chrome.exe",
        )
        assert context.direction == "outbound"
        assert context.port == 443
        assert context.process_name == "chrome.exe"


class TestEvidenceItem:
    """Test EvidenceItem model."""

    def test_evidence_item(self):
        """Test evidence item creation."""
        evidence = EvidenceItem(
            source="abuseipdb",
            category="reputation",
            severity="medium",
            title="High abuse confidence",
            detail="IP has 95% abuse confidence score",
            score_delta=30,
            confidence=0.9,
            raw={"abuse_confidence_score": 95},
        )
        assert evidence.source == "abuseipdb"
        assert evidence.score_delta == 30
        assert evidence.confidence == 0.9


class TestVerdict:
    """Test Verdict model."""

    def test_verdict(self):
        """Test verdict creation."""
        verdict = Verdict(
            object_type="ip",
            object_value="8.8.8.8",
            reputation_score=10,
            contextual_score=0,
            final_score=10,
            level="Low",
            confidence=0.8,
            decision="allow_with_monitoring",
            summary="Low risk IP",
            evidence=[],
            tags=["google_service"],
        )
        assert verdict.level == "Low"
        assert verdict.final_score == 10
        assert "google_service" in verdict.tags
