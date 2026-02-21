#!/usr/bin/env python3
"""
Unified Threat Intelligence & SIEM Fusion System
==================================================
CLI entry point that orchestrates the full pipeline:
  Ingest -> Enrich -> Score -> Graph -> Summarize -> Generate Queries -> Save

Usage:
  python fusion.py
  python fusion.py --local-stix sample_data/stix_bundle.json --logs sample_data/siem_logs.csv
  python fusion.py --config config.yaml --output outputs/
"""

import argparse
import logging
import sys
import os
from pathlib import Path
from datetime import datetime

import yaml

from threat_intel.ingestion import ingest_all_feeds
from threat_intel.enrichment import load_siem_logs, enrich_logs, get_enriched_alerts, get_alert_summary
from threat_intel.scoring import calculate_risk_scores, get_risk_summary
from threat_intel.graph_builder import build_threat_graph, export_graph_png, export_graph_html
from threat_intel.llm_summarizer import generate_summary, save_summary
from threat_intel.query_generator import generate_all_queries, save_queries
from threat_intel.storage import IOCDatabase, export_json, export_csv, export_enriched_alerts


# ── Logging Setup ────────────────────────────────────────────────────────
def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(level=level, format=fmt, datefmt="%Y-%m-%d %H:%M:%S")


# ── Config Loading ───────────────────────────────────────────────────────
def load_config(config_path: str) -> dict:
    p = Path(config_path)
    if p.exists():
        with open(p, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    return {}


# ── CLI Argument Parsing ─────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="Unified Threat Intelligence & SIEM Fusion System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python fusion.py                                          # Use config.yaml defaults
  python fusion.py --local-stix data/bundle.json            # Specify STIX file
  python fusion.py --logs siem.csv --output results/        # Custom logs & output
  python fusion.py --llm-provider groq --verbose            # With LLM & debug logging
        """
    )

    parser.add_argument('--config', default='config.yaml',
                        help='Path to configuration file (default: config.yaml)')
    parser.add_argument('--local-stix', nargs='+',
                        help='Local STIX bundle JSON file(s)')
    parser.add_argument('--osint', nargs='+',
                        help='OSINT feed CSV/JSON file(s)')
    parser.add_argument('--logs', nargs='+',
                        help='SIEM log CSV file(s)')
    parser.add_argument('--output', default=None,
                        help='Output directory (default: from config or ./outputs)')
    parser.add_argument('--llm-provider', choices=['groq', 'none'], default=None,
                        help='LLM provider for summaries (default: from config)')
    parser.add_argument('--format', nargs='+', choices=['json', 'csv'], default=None,
                        help='Output formats (default: both)')
    parser.add_argument('--graph-format', choices=['png', 'html', 'both'], default=None,
                        help='Graph export format (default: from config)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose/debug logging')
    parser.add_argument('--no-graph', action='store_true',
                        help='Skip graph generation')
    parser.add_argument('--no-llm', action='store_true',
                        help='Skip LLM summarization (use template)')
    parser.add_argument('--no-queries', action='store_true',
                        help='Skip query generation')

    return parser.parse_args()


# ── Banner ───────────────────────────────────────────────────────────────
def print_banner():
    banner = """
    +==================================================================+
    |       Unified Threat Intelligence & SIEM Fusion System           |
    |                         v1.0.0                                   |
    +==================================================================+
    |  Ingest -> Enrich -> Score -> Graph -> Summarize -> Hunt Queries  |
    +==================================================================+
    """
    print(banner)


# ── Main Pipeline ────────────────────────────────────────────────────────
def main():
    args = parse_args()
    setup_logging(args.verbose)
    logger = logging.getLogger("fusion")

    print_banner()

    # Load config
    config = load_config(args.config)

    # Override config with CLI arguments
    if args.local_stix:
        config.setdefault('feeds', {})['local_stix'] = args.local_stix
    if args.osint:
        config.setdefault('feeds', {})['osint_feeds'] = args.osint
    if args.logs:
        config.setdefault('siem', {})['log_files'] = args.logs
    if args.llm_provider:
        config.setdefault('llm', {})['provider'] = args.llm_provider
    if args.no_llm:
        config.setdefault('llm', {})['provider'] = 'none'

    output_dir = args.output or config.get('output', {}).get('directory', 'outputs')
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    output_formats = args.format or config.get('output', {}).get('formats', ['json', 'csv'])
    graph_format = args.graph_format or config.get('output', {}).get('graph_format', 'png')

    # ── Step 1: Ingest Threat Feeds ──────────────────────────────────
    print("\n[*] Step 1/6: Ingesting threat feeds...")
    logger.info("=" * 60)
    logger.info("STEP 1: Ingesting threat feeds")
    logger.info("=" * 60)

    iocs, stix_parser = ingest_all_feeds(config)
    if not iocs:
        logger.error("No IOCs ingested. Check your feed configuration.")
        print("[X] No IOCs found. Verify your feed sources in config.yaml")
        sys.exit(1)

    print(f"   [+] Ingested {len(iocs)} unique IOCs")
    print(f"   [i] Actors: {len(stix_parser.actors)} | Malware: {len(stix_parser.malware)} | "
          f"TTPs: {len(stix_parser.attack_patterns)}")

    # ── Step 2: Load & Enrich SIEM Logs ──────────────────────────────
    print("\n[*] Step 2/6: Loading and enriching SIEM logs...")
    logger.info("=" * 60)
    logger.info("STEP 2: Loading and enriching SIEM logs")
    logger.info("=" * 60)

    log_files = config.get('siem', {}).get('log_files', [])
    column_mapping = config.get('siem', {}).get('column_mapping', {})
    logs = load_siem_logs(log_files, column_mapping)

    if logs.empty:
        logger.warning("No SIEM logs loaded. Scoring will not include sightings data.")
        print("   [!] No SIEM logs loaded. Continuing without enrichment.")
        enriched_logs = logs
        enrichment_summary = {"total_alerts": 0}
    else:
        enriched_logs = enrich_logs(logs, iocs)
        malicious_alerts = get_enriched_alerts(enriched_logs)
        enrichment_summary = get_alert_summary(malicious_alerts)

        print(f"   [+] Processed {len(logs)} log entries")
        print(f"   [!] Found {enrichment_summary['total_alerts']} malicious matches")
        print(f"   [i] Actors detected: {', '.join(enrichment_summary.get('actors', []))}")

    # ── Step 3: Risk Scoring ─────────────────────────────────────────
    print("\n[*] Step 3/6: Calculating risk scores...")
    logger.info("=" * 60)
    logger.info("STEP 3: Risk scoring")
    logger.info("=" * 60)

    scoring_weights = config.get('scoring', {}).get('weights', None)
    scored_iocs = calculate_risk_scores(iocs, enriched_logs, scoring_weights)
    risk_summary = get_risk_summary(scored_iocs)

    print(f"   [+] Scored {len(scored_iocs)} IOCs")
    print(f"   Critical: {risk_summary.get('critical_count', 0)} | "
          f"High: {risk_summary.get('high_count', 0)} | "
          f"Medium: {risk_summary.get('medium_count', 0)} | "
          f"Low: {risk_summary.get('low_count', 0)}")

    # ── Step 4: Graph Visualization ──────────────────────────────────
    if not args.no_graph:
        print("\n[*] Step 4/6: Building attacker infrastructure graph...")
        logger.info("=" * 60)
        logger.info("STEP 4: Graph visualization")
        logger.info("=" * 60)

        G = build_threat_graph(stix_parser, scored_iocs)

        if graph_format in ('png', 'both'):
            export_graph_png(G, os.path.join(output_dir, 'attacker_graph.png'))
            print(f"   [+] Graph exported: {output_dir}/attacker_graph.png")
        if graph_format in ('html', 'both'):
            export_graph_html(G, os.path.join(output_dir, 'attacker_graph.html'))
            print(f"   [+] Interactive graph: {output_dir}/attacker_graph.html")
    else:
        print("\n[>] Step 4/6: Graph generation skipped")

    # ── Step 5: LLM Summary ──────────────────────────────────────────
    print("\n[*] Step 5/6: Generating threat campaign summary...")
    logger.info("=" * 60)
    logger.info("STEP 5: LLM summarization")
    logger.info("=" * 60)

    summary = generate_summary(scored_iocs, stix_parser, enrichment_summary, config)
    summary_path = os.path.join(output_dir, 'threat_summary.md')
    save_summary(summary, summary_path)
    print(f"   [+] Summary saved: {summary_path}")

    # ── Step 6: Hunt Queries ─────────────────────────────────────────
    if not args.no_queries:
        print("\n[*] Step 6/6: Generating threat hunting queries...")
        logger.info("=" * 60)
        logger.info("STEP 6: Query generation")
        logger.info("=" * 60)

        queries = generate_all_queries(scored_iocs)
        save_queries(queries, output_dir)
        print(f"   [+] Queries saved: SPL, KQL, Elasticsearch DSL")
    else:
        print("\n[>] Step 6/6: Query generation skipped")

    # ── Save Results ─────────────────────────────────────────────────
    print(f"\n[*] Saving results to {output_dir}/...")

    if 'json' in output_formats:
        export_json(scored_iocs, os.path.join(output_dir, 'risk_ranked_iocs.json'))
    if 'csv' in output_formats:
        export_csv(scored_iocs, os.path.join(output_dir, 'risk_ranked_iocs.csv'))

    if not enriched_logs.empty:
        export_enriched_alerts(enriched_logs, os.path.join(output_dir, 'enriched_alerts.csv'))

    # Store in SQLite
    db_path = config.get('storage', {}).get('database', 'threat_intel.db')
    db = IOCDatabase(db_path)
    db.store_scored_iocs(scored_iocs)
    if not enriched_logs.empty:
        db.store_enriched_alerts(enriched_logs)

    # ── Final Report ─────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("[+] FUSION PIPELINE COMPLETE")
    print("=" * 60)
    print(f"\n  Output directory: {os.path.abspath(output_dir)}")
    print(f"  Total IOCs scored: {len(scored_iocs)}")
    print(f"  Malicious alerts: {enrichment_summary.get('total_alerts', 0)}")
    print(f"  Database: {os.path.abspath(db_path)}")
    print(f"\n  Generated files:")

    for f in sorted(Path(output_dir).iterdir()):
        size = f.stat().st_size
        if size > 1024:
            size_str = f"{size / 1024:.1f} KB"
        else:
            size_str = f"{size} B"
        print(f"   - {f.name} ({size_str})")

    print()


if __name__ == "__main__":
    main()
