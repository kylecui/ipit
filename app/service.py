"""
Main service interface for threat intelligence analysis.
"""

from typing import Optional
from models import Observable, ContextProfile, Verdict
from app.query_engine import QueryEngine


class ThreatIntelService:
    """Main service class for threat intelligence analysis."""

    def __init__(self):
        self.query_engine = QueryEngine()

    async def analyze_ip(
        self, ip: str, context: Optional[ContextProfile] = None, refresh: bool = False
    ) -> Verdict:
        """Analyze an IP address for threats."""
        observable = Observable(type="ip", value=ip)
        return await self.query_engine.analyze(observable, context, refresh)

    async def analyze_domain(
        self,
        domain: str,
        context: Optional[ContextProfile] = None,
        refresh: bool = False,
    ) -> Verdict:
        """Analyze a domain for threats."""
        observable = Observable(type="domain", value=domain)
        return await self.query_engine.analyze(observable, context, refresh)

    async def analyze_url(
        self, url: str, context: Optional[ContextProfile] = None, refresh: bool = False
    ) -> Verdict:
        """Analyze a URL for threats."""
        observable = Observable(type="url", value=url)
        return await self.query_engine.analyze(observable, context, refresh)
