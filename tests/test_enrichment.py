"""Tests for SIEM log enrichment module."""

import pytest
from pathlib import Path

from threat_intel.ingestion import ingest_all_feeds
from threat_intel.enrichment import load_siem_logs, enrich_logs, get_enriched_alerts, get_alert_summary


SAMPLE_DATA_DIR = Path(__file__).parent.parent / "sample_data"


@pytest.fixture
def sample_config():
    return {
        'feeds': {
            'local_stix': [str(SAMPLE_DATA_DIR / "stix_bundle.json")],
            'osint_feeds': [str(SAMPLE_DATA_DIR / "osint_feed.csv")],
            'taxii_servers': [],
        }
    }


@pytest.fixture
def iocs(sample_config):
    iocs, _ = ingest_all_feeds(sample_config)
    return iocs


class TestLoadSIEMLogs:
    def test_load_logs(self):
        logs = load_siem_logs([str(SAMPLE_DATA_DIR / "siem_logs.csv")])
        assert not logs.empty
        assert 'src_ip' in logs.columns
        assert 'dst_ip' in logs.columns
        assert len(logs) == 50  # 50 sample entries

    def test_missing_file(self):
        logs = load_siem_logs(["nonexistent.csv"])
        assert logs.empty


class TestEnrichment:
    def test_enrich_finds_matches(self, iocs):
        logs = load_siem_logs([str(SAMPLE_DATA_DIR / "siem_logs.csv")])
        enriched = enrich_logs(logs, iocs)

        assert 'matched_ioc' in enriched.columns
        assert 'threat_actor' in enriched.columns
        assert 'is_malicious' in enriched.columns

        malicious = enriched[enriched['is_malicious'] == True]
        assert len(malicious) > 0, "Should find malicious matches"

    def test_enrichment_columns(self, iocs):
        logs = load_siem_logs([str(SAMPLE_DATA_DIR / "siem_logs.csv")])
        enriched = enrich_logs(logs, iocs)

        expected_cols = ['matched_ioc', 'ioc_type', 'threat_actor', 'ttp',
                         'ioc_confidence', 'malware_family', 'is_malicious']
        for col in expected_cols:
            assert col in enriched.columns, f"Missing column: {col}"

    def test_alert_summary(self, iocs):
        logs = load_siem_logs([str(SAMPLE_DATA_DIR / "siem_logs.csv")])
        enriched = enrich_logs(logs, iocs)
        alerts = get_enriched_alerts(enriched)
        summary = get_alert_summary(alerts)

        assert summary['total_alerts'] > 0
        assert len(summary['actors']) > 0
        assert len(summary['affected_hosts']) > 0
