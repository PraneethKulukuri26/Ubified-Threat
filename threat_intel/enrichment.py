"""
SIEM Log Enrichment Module
============================
Loads SIEM logs from CSV, matches them against ingested IOCs,
and appends threat context (actor, TTP, campaign, malware family).
"""

import logging
from typing import List, Optional
from pathlib import Path

import pandas as pd

from .ingestion import IOC

logger = logging.getLogger(__name__)


def load_siem_logs(file_paths: List[str], column_mapping: dict = None) -> pd.DataFrame:
    """
    Load SIEM logs from one or more CSV files into a single DataFrame.
    Applies optional column mapping to normalize field names.
    """
    frames = []
    for path in file_paths:
        p = Path(path)
        if not p.exists():
            logger.warning(f"SIEM log file not found: {path}")
            continue
        try:
            df = pd.read_csv(p, dtype=str).fillna("")
            frames.append(df)
            logger.info(f"Loaded {len(df)} log entries from {p.name}")
        except Exception as e:
            logger.error(f"Error loading SIEM logs from {path}: {e}")

    if not frames:
        logger.warning("No SIEM log files loaded")
        return pd.DataFrame()

    logs = pd.concat(frames, ignore_index=True)

    # Apply column mapping if provided
    if column_mapping:
        reverse_map = {v: k for k, v in column_mapping.items() if v in logs.columns and k != v}
        if reverse_map:
            logs = logs.rename(columns=reverse_map)

    return logs


def enrich_logs(logs: pd.DataFrame, iocs: List[IOC]) -> pd.DataFrame:
    """
    Match IOC values against SIEM log fields and append enrichment context.

    Matching fields:
    - src_ip, dst_ip → ipv4 IOCs
    - domain → domain IOCs
    - hash → sha256/md5 IOCs
    - url → url IOCs

    Added columns: matched_ioc, ioc_type, threat_actor, ttp, confidence,
                   malware_family, ioc_description, ioc_source, ioc_labels
    """
    if logs.empty or not iocs:
        logger.warning("Empty logs or no IOCs to match against")
        return logs

    # Build lookup dictionaries by IOC type
    ip_lookup = {}
    domain_lookup = {}
    hash_lookup = {}
    url_lookup = {}

    for ioc in iocs:
        entry = {
            'ioc_type': ioc.ioc_type,
            'value': ioc.value,
            'actor': ioc.actor,
            'ttp': ioc.ttp,
            'confidence': ioc.confidence,
            'malware_family': ioc.malware_family,
            'description': ioc.description,
            'source': ioc.source,
            'labels': ", ".join(ioc.labels) if ioc.labels else "",
        }

        if ioc.ioc_type in ('ipv4', 'ipv6'):
            ip_lookup[ioc.value] = entry
        elif ioc.ioc_type == 'domain':
            domain_lookup[ioc.value] = entry
        elif ioc.ioc_type in ('sha256', 'md5', 'sha1'):
            hash_lookup[ioc.value] = entry
        elif ioc.ioc_type == 'url':
            url_lookup[ioc.value] = entry

    # Initialize enrichment columns
    enrichment_cols = [
        'matched_ioc', 'ioc_type', 'threat_actor', 'ttp',
        'ioc_confidence', 'malware_family', 'ioc_description',
        'ioc_source', 'ioc_labels', 'is_malicious'
    ]
    for col in enrichment_cols:
        logs[col] = ""
    logs['is_malicious'] = False

    match_count = 0

    for idx, row in logs.iterrows():
        matched = None

        # Check destination IP
        dst_ip = str(row.get('dst_ip', '')).strip()
        if dst_ip and dst_ip in ip_lookup:
            matched = ip_lookup[dst_ip]

        # Check source IP (less common but possible for internal compromised hosts)
        if not matched:
            src_ip = str(row.get('src_ip', '')).strip()
            if src_ip and src_ip in ip_lookup:
                matched = ip_lookup[src_ip]

        # Check domain
        if not matched:
            domain = str(row.get('domain', '')).strip()
            if domain and domain in domain_lookup:
                matched = domain_lookup[domain]

        # Check hash
        if not matched:
            file_hash = str(row.get('hash', '')).strip()
            if file_hash and file_hash in hash_lookup:
                matched = hash_lookup[file_hash]

        # Check URL
        if not matched:
            url = str(row.get('url', '')).strip()
            if url:
                for ioc_url, entry in url_lookup.items():
                    if ioc_url in url:
                        matched = entry
                        break

        if matched:
            logs.at[idx, 'matched_ioc'] = matched['value']
            logs.at[idx, 'ioc_type'] = matched['ioc_type']
            logs.at[idx, 'threat_actor'] = matched['actor']
            logs.at[idx, 'ttp'] = matched['ttp']
            logs.at[idx, 'ioc_confidence'] = matched['confidence']
            logs.at[idx, 'malware_family'] = matched['malware_family']
            logs.at[idx, 'ioc_description'] = matched['description']
            logs.at[idx, 'ioc_source'] = matched['source']
            logs.at[idx, 'ioc_labels'] = matched['labels']
            logs.at[idx, 'is_malicious'] = True
            match_count += 1

    malicious = logs[logs['is_malicious'] == True]
    benign = logs[logs['is_malicious'] == False]

    logger.info(f"Enrichment complete: {match_count} matches found in {len(logs)} log entries")
    logger.info(f"  Malicious: {len(malicious)} | Benign: {len(benign)}")

    return logs


def get_enriched_alerts(logs: pd.DataFrame) -> pd.DataFrame:
    """Return only log entries that matched an IOC (threats only)."""
    if 'is_malicious' not in logs.columns:
        return pd.DataFrame()
    return logs[logs['is_malicious'] == True].copy()


def get_alert_summary(enriched: pd.DataFrame) -> dict:
    """Generate a summary of enriched alerts."""
    if enriched.empty:
        return {"total_alerts": 0, "actors": [], "ioc_types": {}, "affected_hosts": []}

    return {
        "total_alerts": len(enriched),
        "unique_iocs": enriched['matched_ioc'].nunique(),
        "actors": enriched['threat_actor'].unique().tolist(),
        "ioc_types": enriched['ioc_type'].value_counts().to_dict(),
        "affected_hosts": enriched['src_ip'].unique().tolist() if 'src_ip' in enriched.columns else [],
        "severity_distribution": enriched['severity'].value_counts().to_dict() if 'severity' in enriched.columns else {},
        "top_targeted_ips": enriched['dst_ip'].value_counts().head(5).to_dict() if 'dst_ip' in enriched.columns else {},
    }
