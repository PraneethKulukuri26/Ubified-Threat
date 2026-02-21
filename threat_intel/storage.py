"""
IOC Storage Module
====================
Handles persistence of IOCs and enriched data via SQLite and CSV/JSON export.
"""

import json
import csv
import sqlite3
import logging
from typing import List, Dict
from pathlib import Path
from datetime import datetime

import pandas as pd

from .scoring import ScoredIOC

logger = logging.getLogger(__name__)


class IOCDatabase:
    """SQLite-backed IOC storage with deduplication."""

    def __init__(self, db_path: str = "threat_intel.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize the database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT,
                actor TEXT DEFAULT 'Unknown',
                ttp TEXT DEFAULT '',
                confidence TEXT DEFAULT 'medium',
                malware_family TEXT DEFAULT '',
                description TEXT DEFAULT '',
                risk_score REAL DEFAULT 0.0,
                severity_label TEXT DEFAULT '',
                sightings INTEGER DEFAULT 0,
                labels TEXT DEFAULT '',
                first_seen TEXT,
                last_seen TEXT,
                UNIQUE(ioc_type, value)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS enriched_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                domain TEXT,
                url TEXT,
                hash TEXT,
                event_type TEXT,
                severity TEXT,
                matched_ioc TEXT,
                ioc_type TEXT,
                threat_actor TEXT,
                ttp TEXT,
                malware_family TEXT,
                ioc_source TEXT,
                ingested_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        conn.commit()
        conn.close()
        logger.info(f"Database initialized: {self.db_path}")

    def store_scored_iocs(self, scored_iocs: List[ScoredIOC]):
        """Store or update scored IOCs in the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()

        for ioc in scored_iocs:
            cursor.execute('''
                INSERT INTO iocs (ioc_type, value, source, actor, ttp, confidence,
                                  malware_family, description, risk_score, severity_label,
                                  sightings, labels, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ioc_type, value) DO UPDATE SET
                    risk_score = excluded.risk_score,
                    severity_label = excluded.severity_label,
                    sightings = excluded.sightings,
                    actor = CASE WHEN excluded.actor != 'Unknown' THEN excluded.actor ELSE iocs.actor END,
                    last_seen = excluded.last_seen,
                    confidence = excluded.confidence
            ''', (
                ioc.ioc_type, ioc.value, ioc.source, ioc.actor, ioc.ttp,
                ioc.confidence, ioc.malware_family, ioc.description,
                ioc.risk_score, ioc.severity_label, ioc.sightings,
                ", ".join(ioc.labels) if ioc.labels else "",
                now, now
            ))

        conn.commit()
        conn.close()
        logger.info(f"Stored {len(scored_iocs)} IOCs in database")

    def store_enriched_alerts(self, enriched_df: pd.DataFrame):
        """Store enriched alert data in the database."""
        if enriched_df.empty:
            return

        conn = sqlite3.connect(self.db_path)
        malicious = enriched_df[enriched_df.get('is_malicious', pd.Series(dtype=bool)) == True]

        for _, row in malicious.iterrows():
            try:
                conn.execute('''
                    INSERT INTO enriched_alerts
                    (timestamp, src_ip, dst_ip, domain, url, hash, event_type,
                     severity, matched_ioc, ioc_type, threat_actor, ttp,
                     malware_family, ioc_source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    str(row.get('timestamp', '')),
                    str(row.get('src_ip', '')),
                    str(row.get('dst_ip', '')),
                    str(row.get('domain', '')),
                    str(row.get('url', '')),
                    str(row.get('hash', '')),
                    str(row.get('event_type', '')),
                    str(row.get('severity', '')),
                    str(row.get('matched_ioc', '')),
                    str(row.get('ioc_type', '')),
                    str(row.get('threat_actor', '')),
                    str(row.get('ttp', '')),
                    str(row.get('malware_family', '')),
                    str(row.get('ioc_source', '')),
                ))
            except Exception as e:
                logger.warning(f"Error storing alert: {e}")

        conn.commit()
        conn.close()
        logger.info(f"Stored {len(malicious)} enriched alerts in database")

    def get_all_iocs(self) -> List[dict]:
        """Retrieve all IOCs from the database."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM iocs ORDER BY risk_score DESC')
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows

    def get_iocs_by_severity(self, severity: str) -> List[dict]:
        """Retrieve IOCs filtered by severity label."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM iocs WHERE severity_label = ? ORDER BY risk_score DESC', (severity,))
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows


def export_json(scored_iocs: List[ScoredIOC], output_path: str):
    """Export scored IOCs to a JSON file."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_iocs": len(scored_iocs),
        "iocs": [ioc.to_dict() for ioc in scored_iocs]
    }
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    logger.info(f"IOCs exported to JSON: {output_path}")


def export_csv(scored_iocs: List[ScoredIOC], output_path: str):
    """Export scored IOCs to a CSV file."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    if not scored_iocs:
        return

    fieldnames = list(scored_iocs[0].to_dict().keys())
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for ioc in scored_iocs:
            row = ioc.to_dict()
            row['labels'] = ", ".join(row['labels']) if isinstance(row['labels'], list) else row['labels']
            writer.writerow(row)
    logger.info(f"IOCs exported to CSV: {output_path}")


def export_enriched_alerts(enriched_df: pd.DataFrame, output_path: str):
    """Export enriched SIEM alerts to CSV."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    malicious = enriched_df[enriched_df.get('is_malicious', pd.Series(dtype=bool)) == True]
    malicious.to_csv(output_path, index=False)
    logger.info(f"Enriched alerts exported to: {output_path}")
