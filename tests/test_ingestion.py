"""Tests for threat feed ingestion module."""

import json
import pytest
from pathlib import Path

from threat_intel.ingestion import (
    STIXParser, LocalSTIXIngester, OSINTIngester, IOC, ingest_all_feeds
)


SAMPLE_DATA_DIR = Path(__file__).parent.parent / "sample_data"


class TestSTIXParser:
    """Test STIX 2.1 bundle parsing."""

    def test_parse_stix_bundle(self):
        with open(SAMPLE_DATA_DIR / "stix_bundle.json") as f:
            bundle = json.load(f)

        parser = STIXParser()
        iocs = parser.parse_bundle(bundle, source="test")

        assert len(iocs) > 0, "Should parse at least one IOC"
        assert len(parser.actors) == 3, "Should find 3 threat actors"
        assert len(parser.malware) == 3, "Should find 3 malware families"
        assert len(parser.attack_patterns) == 3, "Should find 3 attack patterns"
        assert len(parser.relationships) > 0, "Should find relationships"

    def test_ioc_types(self):
        with open(SAMPLE_DATA_DIR / "stix_bundle.json") as f:
            bundle = json.load(f)

        parser = STIXParser()
        iocs = parser.parse_bundle(bundle)

        types = {ioc.ioc_type for ioc in iocs}
        assert 'ipv4' in types, "Should contain IPv4 indicators"
        assert 'domain' in types, "Should contain domain indicators"
        assert 'sha256' in types, "Should contain SHA256 indicators"

    def test_actor_enrichment(self):
        with open(SAMPLE_DATA_DIR / "stix_bundle.json") as f:
            bundle = json.load(f)

        parser = STIXParser()
        iocs = parser.parse_bundle(bundle)

        # At least some IOCs should be attributed to an actor
        attributed = [i for i in iocs if i.actor != "Unknown"]
        assert len(attributed) > 0, "Some IOCs should be attributed to actors"

    def test_pattern_extraction(self):
        parser = STIXParser()

        t, v = parser._extract_from_pattern("[ipv4-addr:value = '1.2.3.4']")
        assert t == 'ipv4'
        assert v == '1.2.3.4'

        t, v = parser._extract_from_pattern("[domain-name:value = 'evil.com']")
        assert t == 'domain'
        assert v == 'evil.com'


class TestOSINTIngester:
    """Test OSINT CSV feed ingestion."""

    def test_load_osint_csv(self):
        ingester = OSINTIngester([str(SAMPLE_DATA_DIR / "osint_feed.csv")])
        iocs = ingester.ingest()

        assert len(iocs) > 0, "Should load IOCs from CSV"
        assert all(isinstance(ioc, IOC) for ioc in iocs)

    def test_osint_fields(self):
        ingester = OSINTIngester([str(SAMPLE_DATA_DIR / "osint_feed.csv")])
        iocs = ingester.ingest()

        for ioc in iocs:
            assert ioc.value, "IOC value should not be empty"
            assert ioc.ioc_type, "IOC type should not be empty"
            assert ioc.source, "IOC source should not be empty"


class TestLocalSTIXIngester:
    """Test local STIX file ingestion."""

    def test_ingest_local_stix(self):
        ingester = LocalSTIXIngester([str(SAMPLE_DATA_DIR / "stix_bundle.json")])
        iocs, parser = ingester.ingest()

        assert len(iocs) > 0
        assert len(parser.actors) > 0

    def test_missing_file(self):
        ingester = LocalSTIXIngester(["nonexistent.json"])
        iocs, parser = ingester.ingest()
        assert len(iocs) == 0


class TestIngestAllFeeds:
    """Test the master ingestion function."""

    def test_ingest_all(self):
        config = {
            'feeds': {
                'local_stix': [str(SAMPLE_DATA_DIR / "stix_bundle.json")],
                'osint_feeds': [str(SAMPLE_DATA_DIR / "osint_feed.csv")],
                'taxii_servers': [],
            }
        }
        iocs, parser = ingest_all_feeds(config)

        assert len(iocs) > 0
        # Should deduplicate overlapping IOCs
        values = [i.value for i in iocs]
        assert len(values) == len(set(values)), "IOCs should be deduplicated"
