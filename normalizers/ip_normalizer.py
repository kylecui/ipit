"""
IP profile normalizer for standardizing collected data.
"""

import logging
from datetime import datetime
from typing import Dict, Any
from models import IPProfile

logger = logging.getLogger(__name__)


class IPNormalizer:
    """Normalizes collected threat intelligence data into IPProfile."""

    def normalize(
        self, ip: str, collected_data: Dict[str, Dict[str, Any]]
    ) -> IPProfile:
        """
        Normalize collected data from all sources into a unified IPProfile.

        Args:
            ip: The IP address being analyzed
            collected_data: Dict mapping source names to their results

        Returns:
            Normalized IPProfile
        """
        profile = IPProfile(ip=ip)

        # Extract data from each source
        if "rdap" in collected_data and collected_data["rdap"]["ok"]:
            self._extract_rdap_data(profile, collected_data["rdap"]["data"])

        if "reverse_dns" in collected_data and collected_data["reverse_dns"]["ok"]:
            self._extract_reverse_dns_data(
                profile, collected_data["reverse_dns"]["data"]
            )

        # Store all raw source data
        profile.sources = collected_data

        # Set timestamps
        profile.timestamps = {
            "normalized_at": datetime.now(),
            "collected_at": datetime.now(),  # This would come from collection time in real impl
        }

        return profile

    def _extract_rdap_data(self, profile: IPProfile, rdap_data: Dict[str, Any]) -> None:
        """Extract organization, network, and ASN data from RDAP."""
        if not rdap_data:
            return

        # Extract organization
        if "name" in rdap_data:
            profile.organization = rdap_data["name"]

        # Extract country
        if "country" in rdap_data:
            profile.country = rdap_data["country"]

        # Extract ASN
        if "asn" in rdap_data:
            profile.asn = rdap_data["asn"]

        # Extract network/CIDR
        if "network" in rdap_data:
            profile.network = rdap_data["network"]

    def _extract_reverse_dns_data(
        self, profile: IPProfile, rdns_data: Dict[str, Any]
    ) -> None:
        """Extract hostname data from reverse DNS."""
        if not rdns_data:
            return

        # Extract primary hostname
        if "hostname" in rdns_data and rdns_data["hostname"]:
            profile.rdns = [rdns_data["hostname"]]

        # Extract aliases as additional hostnames
        if "aliases" in rdns_data and rdns_data["aliases"]:
            profile.hostnames = rdns_data["aliases"]
