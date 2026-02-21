# Unified Threat Intelligence & SIEM Fusion

A Python-based tool that fuses external threat intelligence (STIX/TAXII, OSINT feeds) with internal SIEM logs to produce actionable security outputs.

## Features

- **Threat Feed Ingestion** — STIX 2.1 bundles, TAXII 2.0/2.1 servers, OSINT CSV/JSON feeds
- **SIEM Log Enrichment** — Matches IOCs against firewall/proxy/DNS logs, adds threat context
- **Risk Scoring** — Weighted scoring (recency, actor severity, sightings) with severity labels
- **Attacker Infrastructure Graphs** — NetworkX + Matplotlib/Plotly visualizations
- **LLM Campaign Summaries** — Groq-powered (Llama 3.3 70B) or template-based fallback
- **Hunt Query Generation** — Auto-generated Splunk SPL, Microsoft KQL, Elasticsearch DSL
- **SQLite Storage** — Persistent IOC database with deduplication

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run with sample data (no API key needed)
python fusion.py

# Run with Groq LLM summaries
export GROQ_API_KEY="your-key-here"
python fusion.py

# Custom inputs
python fusion.py --local-stix data/bundle.json --logs siem.csv --output results/
```

## Docker

```bash
# Build and run
docker-compose up --build

# With Groq API key
GROQ_API_KEY=your-key docker-compose up --build
```

## CLI Options

| Flag | Description |
|------|-------------|
| `--config` | Config file path (default: `config.yaml`) |
| `--local-stix` | STIX bundle JSON file(s) |
| `--osint` | OSINT feed CSV/JSON file(s) |
| `--logs` | SIEM log CSV file(s) |
| `--output` | Output directory |
| `--graph-format` | `png`, `html`, or `both` |
| `--no-graph` | Skip graph generation |
| `--no-llm` | Use template summaries |
| `--no-queries` | Skip query generation |
| `-v, --verbose` | Debug logging |

## Output Files

| File | Description |
|------|-------------|
| `risk_ranked_iocs.json/csv` | IOCs sorted by risk score |
| `enriched_alerts.csv` | SIEM logs matched with IOCs |
| `attacker_graph.png/html` | Infrastructure visualization |
| `threat_summary.md` | Campaign summary report |
| `hunt_query.spl/kql/json` | SIEM hunting queries |
| `threat_intel.db` | SQLite IOC database |

## Testing

```bash
pip install pytest
pytest tests/ -v
```

## Project Structure

```
ubified_threat/
├── fusion.py                 # CLI entry point
├── config.yaml               # Configuration
├── requirements.txt          # Dependencies
├── Dockerfile
├── docker-compose.yml
├── threat_intel/
│   ├── __init__.py
│   ├── ingestion.py          # STIX/OSINT/TAXII feed ingestion
│   ├── enrichment.py         # SIEM log enrichment
│   ├── scoring.py            # IOC risk scoring
│   ├── graph_builder.py      # Infrastructure graphs
│   ├── llm_summarizer.py     # Groq LLM summaries
│   ├── query_generator.py    # SPL/KQL/Elastic queries
│   └── storage.py            # SQLite + CSV/JSON export
├── sample_data/
│   ├── stix_bundle.json      # Sample STIX 2.1 bundle
│   ├── siem_logs.csv         # Sample SIEM logs
│   └── osint_feed.csv        # Sample OSINT feed
└── tests/
    ├── test_ingestion.py
    ├── test_enrichment.py
    ├── test_scoring.py
    ├── test_graph_builder.py
    ├── test_query_generator.py
    └── test_integration.py
```
