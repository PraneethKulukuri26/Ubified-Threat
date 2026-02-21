"""End-to-end integration tests for the full fusion pipeline."""

import json
import tempfile
import pytest
from pathlib import Path

from threat_intel.ingestion import ingest_all_feeds
from threat_intel.enrichment import load_siem_logs, enrich_logs, get_enriched_alerts, get_alert_summary
from threat_intel.scoring import calculate_risk_scores, get_risk_summary
from threat_intel.graph_builder import build_threat_graph, export_graph_png
from threat_intel.llm_summarizer import generate_summary
from threat_intel.query_generator import generate_all_queries, save_queries
from threat_intel.storage import IOCDatabase, export_json, export_csv


SAMPLE_DATA_DIR = Path(__file__).parent.parent / "sample_data"


class TestFullPipeline:
    """Test the complete pipeline end-to-end with sample data."""

    def test_full_pipeline(self):
        """Run the entire fusion pipeline and validate all outputs."""
        config = {
            'feeds': {
                'local_stix': [str(SAMPLE_DATA_DIR / "stix_bundle.json")],
                'osint_feeds': [str(SAMPLE_DATA_DIR / "osint_feed.csv")],
                'taxii_servers': [],
            },
            'llm': {'provider': 'none'},
        }

        # Step 1: Ingest
        iocs, parser = ingest_all_feeds(config)
        assert len(iocs) > 0, "Pipeline should produce IOCs"

        # Step 2: Enrich
        logs = load_siem_logs([str(SAMPLE_DATA_DIR / "siem_logs.csv")])
        assert not logs.empty

        enriched = enrich_logs(logs, iocs)
        alerts = get_enriched_alerts(enriched)
        summary = get_alert_summary(alerts)
        assert summary['total_alerts'] > 0, "Should find malicious alerts"

        # Step 3: Score
        scored = calculate_risk_scores(iocs, enriched)
        assert len(scored) > 0
        assert scored[0].risk_score >= scored[-1].risk_score

        # Step 4: Graph
        G = build_threat_graph(parser, scored)
        assert G.number_of_nodes() > 0

        # Step 5: Summary (template mode)
        campaign_summary = generate_summary(scored, parser, summary, config)
        assert len(campaign_summary) > 100, "Summary should be substantial"
        assert "Threat Intelligence" in campaign_summary or "Campaign" in campaign_summary

        # Step 6: Queries
        queries = generate_all_queries(scored)
        assert all(k in queries for k in ['splunk_spl', 'sentinel_kql', 'elastic_dsl'])

        # Step 7: Export
        with tempfile.TemporaryDirectory() as tmpdir:
            export_json(scored, str(Path(tmpdir) / "iocs.json"))
            export_csv(scored, str(Path(tmpdir) / "iocs.csv"))
            export_graph_png(G, str(Path(tmpdir) / "graph.png"))
            save_queries(queries, tmpdir)

            assert (Path(tmpdir) / "iocs.json").exists()
            assert (Path(tmpdir) / "iocs.csv").exists()
            assert (Path(tmpdir) / "graph.png").exists()
            assert (Path(tmpdir) / "hunt_queries.txt").exists()

            # Validate JSON output
            with open(Path(tmpdir) / "iocs.json") as f:
                data = json.load(f)
            assert data['total_iocs'] == len(scored)
            assert len(data['iocs']) == len(scored)

    def test_database_storage(self):
        """Test SQLite storage and retrieval."""
        config = {
            'feeds': {
                'local_stix': [str(SAMPLE_DATA_DIR / "stix_bundle.json")],
                'osint_feeds': [],
                'taxii_servers': [],
            },
        }

        iocs, _ = ingest_all_feeds(config)
        logs = load_siem_logs([str(SAMPLE_DATA_DIR / "siem_logs.csv")])
        enriched = enrich_logs(logs, iocs)
        scored = calculate_risk_scores(iocs, enriched)

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "test.db")
            db = IOCDatabase(db_path)
            db.store_scored_iocs(scored)
            db.store_enriched_alerts(enriched)

            # Retrieve and verify
            stored = db.get_all_iocs()
            assert len(stored) > 0
            assert stored[0]['risk_score'] >= stored[-1]['risk_score']
