"""Tests for threat hunting query generation."""

import pytest
from pathlib import Path

from threat_intel.ingestion import ingest_all_feeds
from threat_intel.enrichment import load_siem_logs, enrich_logs
from threat_intel.scoring import calculate_risk_scores
from threat_intel.query_generator import generate_all_queries


SAMPLE_DATA_DIR = Path(__file__).parent.parent / "sample_data"


@pytest.fixture
def scored_iocs():
    config = {
        'feeds': {
            'local_stix': [str(SAMPLE_DATA_DIR / "stix_bundle.json")],
            'osint_feeds': [str(SAMPLE_DATA_DIR / "osint_feed.csv")],
            'taxii_servers': [],
        }
    }
    iocs, _ = ingest_all_feeds(config)
    logs = load_siem_logs([str(SAMPLE_DATA_DIR / "siem_logs.csv")])
    enriched = enrich_logs(logs, iocs)
    return calculate_risk_scores(iocs, enriched)


class TestQueryGeneration:
    def test_generates_all_platforms(self, scored_iocs):
        queries = generate_all_queries(scored_iocs)

        assert 'splunk_spl' in queries
        assert 'sentinel_kql' in queries
        assert 'elastic_dsl' in queries

    def test_splunk_contains_ips(self, scored_iocs):
        queries = generate_all_queries(scored_iocs)
        spl = queries['splunk_spl']

        assert 'index=security' in spl, "SPL should target security index"
        assert 'src_ip' in spl or 'dst_ip' in spl, "SPL should query IP fields"

    def test_kql_contains_queries(self, scored_iocs):
        queries = generate_all_queries(scored_iocs)
        kql = queries['sentinel_kql']

        assert 'CommonSecurityLog' in kql or 'DeviceNetworkEvents' in kql
        assert 'summarize' in kql.lower() or 'where' in kql.lower()

    def test_elastic_json_valid(self, scored_iocs):
        queries = generate_all_queries(scored_iocs)
        elastic = queries['elastic_dsl']

        # Should contain JSON query structure
        assert '"query"' in elastic
        assert '"bool"' in elastic
