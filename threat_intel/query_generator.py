"""
Auto-Generated Threat Hunting Query Module
=============================================
Generates SIEM hunting queries for Splunk (SPL), Microsoft Sentinel (KQL),
and Elasticsearch (DSL) from scored IOCs.
"""

import json
import logging
from typing import List, Dict
from pathlib import Path
from datetime import datetime

from .scoring import ScoredIOC

logger = logging.getLogger(__name__)


def generate_all_queries(scored_iocs: List[ScoredIOC]) -> Dict[str, str]:
    """
    Generate hunting queries for all SIEM platforms.
    Returns dict with 'splunk_spl', 'sentinel_kql', 'elastic_dsl' keys.
    """
    # Group IOCs by type
    grouped = _group_iocs_by_type(scored_iocs)

    queries = {
        'splunk_spl': generate_splunk_spl(grouped, scored_iocs),
        'sentinel_kql': generate_kql(grouped, scored_iocs),
        'elastic_dsl': generate_elastic_query(grouped, scored_iocs),
    }

    return queries


def _group_iocs_by_type(scored_iocs: List[ScoredIOC]) -> Dict[str, List[str]]:
    """Group IOC values by type."""
    grouped = {
        'ipv4': [],
        'domain': [],
        'sha256': [],
        'md5': [],
        'url': [],
    }
    for ioc in scored_iocs:
        t = ioc.ioc_type
        if t in grouped:
            grouped[t].append(ioc.value)
        elif t in ('ipv6',):
            grouped.setdefault('ipv6', []).append(ioc.value)
    return grouped


def generate_splunk_spl(grouped: Dict[str, List[str]], scored_iocs: List[ScoredIOC]) -> str:
    """Generate Splunk SPL queries for threat hunting."""
    lines = []
    lines.append("=" * 70)
    lines.append("SPLUNK SPL - Threat Hunting Queries")
    lines.append(f"Generated: {datetime.utcnow().isoformat()}Z")
    lines.append("=" * 70)

    # IP-based hunt
    ips = grouped.get('ipv4', [])
    if ips:
        ip_list = ", ".join(f'"{ip}"' for ip in ips)
        lines.append("\n" + "-" * 40)
        lines.append("### Hunt: Malicious IP Connections")
        lines.append("-" * 40)
        lines.append(f'index=security (src_ip IN ({ip_list}) OR dst_ip IN ({ip_list}))')
        lines.append('| stats count by src_ip, dst_ip, action, severity')
        lines.append('| sort -count')
        lines.append("")

        # Per-actor IP queries
        actors = {}
        for ioc in scored_iocs:
            if ioc.ioc_type == 'ipv4' and ioc.actor != 'Unknown':
                actors.setdefault(ioc.actor, []).append(ioc.value)
        for actor, actor_ips in actors.items():
            ip_str = ", ".join(f'"{ip}"' for ip in actor_ips)
            lines.append(f'\n### Hunt: {actor} Infrastructure')
            lines.append(f'index=security (src_ip IN ({ip_str}) OR dst_ip IN ({ip_str}))')
            lines.append(f'| eval threat_actor="{actor}"')
            lines.append('| stats count, values(src_ip) as sources by dst_ip, threat_actor')
            lines.append('| sort -count')

    # Domain-based hunt
    domains = grouped.get('domain', [])
    if domains:
        domain_list = ", ".join(f'"{d}"' for d in domains)
        lines.append("\n" + "-" * 40)
        lines.append("### Hunt: Malicious Domain Lookups")
        lines.append("-" * 40)
        lines.append(f'index=dns query IN ({domain_list})')
        lines.append('| stats count by query, src_ip, answer')
        lines.append('| sort -count')
        lines.append("")
        lines.append(f'index=proxy dest_host IN ({domain_list})')
        lines.append('| stats count by src_ip, dest_host, url, action')
        lines.append('| sort -count')

    # Hash-based hunt
    hashes = grouped.get('sha256', []) + grouped.get('md5', [])
    if hashes:
        hash_list = ", ".join(f'"{h}"' for h in hashes)
        lines.append("\n" + "-" * 40)
        lines.append("### Hunt: Malicious File Hashes")
        lines.append("-" * 40)
        lines.append(f'index=endpoint (file_hash IN ({hash_list}) OR sha256 IN ({hash_list}))')
        lines.append('| stats count by file_hash, file_name, dest, action')
        lines.append('| sort -count')

    # Timeline query
    lines.append("\n" + "-" * 40)
    lines.append("### Hunt: Full Timeline of Threat Activity")
    lines.append("-" * 40)
    all_iocs = ips + domains + hashes
    if all_iocs:
        ioc_str = " OR ".join(f'"{v}"' for v in all_iocs[:50])
        lines.append(f'index=security OR index=dns OR index=endpoint ({ioc_str})')
        lines.append('| timechart span=1h count by sourcetype')

    return "\n".join(lines)


def generate_kql(grouped: Dict[str, List[str]], scored_iocs: List[ScoredIOC]) -> str:
    """Generate Microsoft Sentinel KQL queries for threat hunting."""
    lines = []
    lines.append("=" * 70)
    lines.append("// MICROSOFT SENTINEL KQL - Threat Hunting Queries")
    lines.append(f"// Generated: {datetime.utcnow().isoformat()}Z")
    lines.append("=" * 70)

    # IP-based hunt
    ips = grouped.get('ipv4', [])
    if ips:
        ip_list = ", ".join(f'"{ip}"' for ip in ips)
        lines.append("\n// --- Hunt: Malicious IP Connections ---")
        lines.append("CommonSecurityLog")
        lines.append(f'| where DestinationIP in ({ip_list}) or SourceIP in ({ip_list})')
        lines.append("| summarize ConnectionCount=count() by SourceIP, DestinationIP, "
                      "DeviceAction, LogSeverity")
        lines.append("| sort by ConnectionCount desc")
        lines.append("")

        # Network connections
        lines.append("// --- Hunt: Network Connections to Threat IPs ---")
        lines.append("DeviceNetworkEvents")
        lines.append(f'| where RemoteIP in ({ip_list})')
        lines.append("| summarize count() by DeviceName, RemoteIP, RemotePort, "
                      "InitiatingProcessFileName")
        lines.append("| sort by count_ desc")

    # Domain-based hunt
    domains = grouped.get('domain', [])
    if domains:
        domain_list = ", ".join(f'"{d}"' for d in domains)
        lines.append("\n// --- Hunt: Malicious DNS Lookups ---")
        lines.append("DnsEvents")
        lines.append(f'| where Name in ({domain_list})')
        lines.append("| summarize QueryCount=count() by Name, ClientIP, IPAddresses")
        lines.append("| sort by QueryCount desc")

    # Hash-based hunt
    hashes = grouped.get('sha256', []) + grouped.get('md5', [])
    if hashes:
        hash_list = ", ".join(f'"{h}"' for h in hashes)
        lines.append("\n// --- Hunt: Malicious File Activity ---")
        lines.append("DeviceFileEvents")
        lines.append(f'| where SHA256 in ({hash_list})')
        lines.append("| summarize count() by DeviceName, FileName, FolderPath, SHA256, "
                      "ActionType")
        lines.append("| sort by count_ desc")

    # Timeline
    lines.append("\n// --- Hunt: Threat Activity Timeline ---")
    lines.append("union CommonSecurityLog, DnsEvents, DeviceFileEvents")
    if ips:
        lines.append(f'| where DestinationIP in ({ip_list}) or SourceIP in ({ip_list})')
    lines.append("| summarize count() by bin(TimeGenerated, 1h), Type")
    lines.append("| render timechart")

    return "\n".join(lines)


def generate_elastic_query(grouped: Dict[str, List[str]], scored_iocs: List[ScoredIOC]) -> str:
    """Generate Elasticsearch DSL JSON queries for threat hunting."""
    queries = {}

    # IP-based query
    ips = grouped.get('ipv4', [])
    if ips:
        queries['malicious_ip_connections'] = {
            "query": {
                "bool": {
                    "should": [
                        {"terms": {"destination.ip": ips}},
                        {"terms": {"source.ip": ips}},
                    ],
                    "minimum_should_match": 1
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": 1000
        }

    # Domain-based query
    domains = grouped.get('domain', [])
    if domains:
        queries['malicious_dns_lookups'] = {
            "query": {
                "bool": {
                    "should": [
                        {"terms": {"dns.question.name": domains}},
                        {"terms": {"url.domain": domains}},
                    ],
                    "minimum_should_match": 1
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": 1000
        }

    # Hash-based query
    hashes = grouped.get('sha256', []) + grouped.get('md5', [])
    if hashes:
        queries['malicious_file_hashes'] = {
            "query": {
                "bool": {
                    "should": [
                        {"terms": {"file.hash.sha256": hashes}},
                        {"terms": {"file.hash.md5": hashes}},
                    ],
                    "minimum_should_match": 1
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": 1000
        }

    # Format as readable JSON
    output_lines = []
    output_lines.append("=" * 70)
    output_lines.append("ELASTICSEARCH DSL - Threat Hunting Queries")
    output_lines.append(f"Generated: {datetime.utcnow().isoformat()}Z")
    output_lines.append("=" * 70)

    for name, query in queries.items():
        output_lines.append(f"\n### {name.replace('_', ' ').title()}")
        output_lines.append(f"POST /security-*/_search")
        output_lines.append(json.dumps(query, indent=2))

    return "\n".join(output_lines)


def save_queries(queries: Dict[str, str], output_dir: str):
    """Save all query types to separate files."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Save combined file
    combined = []
    for platform, query_text in queries.items():
        combined.append(query_text)
        combined.append("\n\n")

    combined_path = output_path / "hunt_queries.txt"
    with open(combined_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(combined))

    # Save individual files
    for platform, query_text in queries.items():
        ext = {'splunk_spl': '.spl', 'sentinel_kql': '.kql', 'elastic_dsl': '.json'}
        filename = f"hunt_query{ext.get(platform, '.txt')}"
        filepath = output_path / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(query_text)

    logger.info(f"Hunt queries saved to {output_dir}")
