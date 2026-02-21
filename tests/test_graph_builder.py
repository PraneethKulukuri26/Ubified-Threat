"""Tests for attacker infrastructure graph builder."""

import json
import pytest
import tempfile
from pathlib import Path

from threat_intel.ingestion import STIXParser
from threat_intel.graph_builder import build_threat_graph, export_graph_png


SAMPLE_DATA_DIR = Path(__file__).parent.parent / "sample_data"


@pytest.fixture
def parser():
    with open(SAMPLE_DATA_DIR / "stix_bundle.json") as f:
        bundle = json.load(f)
    p = STIXParser()
    p.parse_bundle(bundle)
    return p


class TestGraphBuilder:
    def test_builds_graph(self, parser):
        G = build_threat_graph(parser)
        assert G.number_of_nodes() > 0, "Graph should have nodes"
        assert G.number_of_edges() > 0, "Graph should have edges"

    def test_nodes_have_types(self, parser):
        G = build_threat_graph(parser)
        for _, data in G.nodes(data=True):
            assert 'node_type' in data, "Each node should have node_type"

    def test_actor_nodes_present(self, parser):
        G = build_threat_graph(parser)
        actor_nodes = [n for n, d in G.nodes(data=True) if d.get('node_type') == 'threat-actor']
        assert len(actor_nodes) == 3, "Should have 3 threat actor nodes"

    def test_export_png(self, parser):
        G = build_threat_graph(parser)
        with tempfile.TemporaryDirectory() as tmpdir:
            output = str(Path(tmpdir) / "test_graph.png")
            export_graph_png(G, output)
            assert Path(output).exists(), "PNG file should be created"
            assert Path(output).stat().st_size > 0
