"""Tests for IOC risk scoring module."""

import pytest
from pathlib import Path
from datetime import datetime, timezone

from threat_intel.ingestion import ingest_all_feeds
from threat_intel.enrichment import load_siem_logs, enrich_logs
from threat_intel.scoring import calculate_risk_scores, get_risk_summary, ScoredIOC


SAMPLE_DATA_DIR = Path(__file__).parent.parent / "sample_data"


@pytest.fixture
def pipeline_data():
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
    return iocs, enriched


class TestScoring:
    def test_calculates_scores(self, pipeline_data):
        iocs, enriched = pipeline_data
        scored = calculate_risk_scores(iocs, enriched)

        assert len(scored) == len(iocs)
        assert all(isinstance(s, ScoredIOC) for s in scored)

    def test_scores_sorted_descending(self, pipeline_data):
        iocs, enriched = pipeline_data
        scored = calculate_risk_scores(iocs, enriched)

        for i in range(len(scored) - 1):
            assert scored[i].risk_score >= scored[i + 1].risk_score, \
                "IOCs should be sorted by risk score descending"

    def test_severity_labels(self, pipeline_data):
        iocs, enriched = pipeline_data
        scored = calculate_risk_scores(iocs, enriched)

        valid_labels = {"Critical", "High", "Medium", "Low"}
        for s in scored:
            assert s.severity_label in valid_labels, f"Invalid label: {s.severity_label}"

    def test_sightings_counted(self, pipeline_data):
        iocs, enriched = pipeline_data
        scored = calculate_risk_scores(iocs, enriched)

        # IOCs that appear in logs should have sightings > 0
        has_sightings = [s for s in scored if s.sightings > 0]
        assert len(has_sightings) > 0, "Some IOCs should have sightings from logs"

    def test_risk_summary(self, pipeline_data):
        iocs, enriched = pipeline_data
        scored = calculate_risk_scores(iocs, enriched)
        summary = get_risk_summary(scored)

        assert summary['total'] == len(scored)
        assert 'top_5' in summary
        assert len(summary['top_5']) <= 5
