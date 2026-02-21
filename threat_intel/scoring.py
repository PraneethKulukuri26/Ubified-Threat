"""
IOC Risk Scoring Module
========================
Calculates risk scores for IOCs based on recency, actor severity,
and sighting frequency in SIEM logs. Ranks and labels IOCs.
"""

import logging
from datetime import datetime, timezone
from typing import List, Dict
from dataclasses import dataclass

import pandas as pd

from .ingestion import IOC

logger = logging.getLogger(__name__)


@dataclass
class ScoredIOC:
    """IOC with calculated risk score and severity label."""
    ioc_type: str
    value: str
    source: str
    actor: str
    ttp: str
    confidence: str
    malware_family: str
    description: str
    risk_score: float
    severity_label: str
    sightings: int
    recency_days: float
    labels: List[str]

    def to_dict(self) -> dict:
        return {
            'ioc_type': self.ioc_type,
            'value': self.value,
            'source': self.source,
            'actor': self.actor,
            'ttp': self.ttp,
            'confidence': self.confidence,
            'malware_family': self.malware_family,
            'description': self.description,
            'risk_score': round(self.risk_score, 3),
            'severity_label': self.severity_label,
            'sightings': self.sightings,
            'recency_days': round(self.recency_days, 1),
            'labels': self.labels,
        }


def calculate_risk_scores(
    iocs: List[IOC],
    enriched_logs: pd.DataFrame,
    weights: dict = None,
    reference_time: datetime = None
) -> List[ScoredIOC]:
    """
    Score each IOC based on:
    - Recency (weight: 0.4): How recently the IOC was reported
    - Actor Severity (weight: 0.3): Confidence/severity of attribution
    - Sightings (weight: 0.3): How many times it appeared in SIEM logs

    Returns list of ScoredIOC sorted by risk_score descending.
    """
    if weights is None:
        weights = {'recency': 0.4, 'actor_severity': 0.3, 'sightings': 0.3}

    if reference_time is None:
        reference_time = datetime.now(timezone.utc)

    # Count sightings per IOC value from enriched logs
    sighting_counts = {}
    if not enriched_logs.empty and 'matched_ioc' in enriched_logs.columns:
        malicious = enriched_logs[enriched_logs.get('is_malicious', pd.Series(dtype=bool)) == True]
        if not malicious.empty:
            sighting_counts = malicious['matched_ioc'].value_counts().to_dict()

    max_sightings = max(sighting_counts.values()) if sighting_counts else 1

    scored_iocs = []
    for ioc in iocs:
        # 1. Recency score (0-1): newer = higher
        recency_days = _calculate_recency_days(ioc.timestamp, reference_time)
        if recency_days <= 1:
            recency_score = 1.0
        elif recency_days <= 7:
            recency_score = 0.8
        elif recency_days <= 30:
            recency_score = 0.6
        elif recency_days <= 90:
            recency_score = 0.4
        else:
            recency_score = 0.2

        # 2. Actor severity score (0-1)
        severity_map = {'critical': 1.0, 'high': 0.8, 'medium': 0.5, 'low': 0.3}
        actor_score = severity_map.get(ioc.confidence, 0.5)

        # Boost if attributed to a known actor
        if ioc.actor and ioc.actor != "Unknown":
            actor_score = min(1.0, actor_score + 0.15)

        # 3. Sighting score (0-1): normalized by max
        sightings = sighting_counts.get(ioc.value, 0)
        sighting_score = min(1.0, sightings / max_sightings) if max_sightings > 0 else 0

        # Weighted composite score
        risk_score = (
            weights['recency'] * recency_score +
            weights['actor_severity'] * actor_score +
            weights['sightings'] * sighting_score
        )

        # Severity label
        severity_label = _score_to_label(risk_score)

        scored = ScoredIOC(
            ioc_type=ioc.ioc_type,
            value=ioc.value,
            source=ioc.source,
            actor=ioc.actor,
            ttp=ioc.ttp,
            confidence=ioc.confidence,
            malware_family=ioc.malware_family,
            description=ioc.description,
            risk_score=risk_score,
            severity_label=severity_label,
            sightings=sightings,
            recency_days=recency_days,
            labels=ioc.labels,
        )
        scored_iocs.append(scored)

    # Sort by risk score descending
    scored_iocs.sort(key=lambda x: x.risk_score, reverse=True)

    logger.info(f"Scored {len(scored_iocs)} IOCs. "
                f"Critical: {sum(1 for s in scored_iocs if s.severity_label == 'Critical')} | "
                f"High: {sum(1 for s in scored_iocs if s.severity_label == 'High')} | "
                f"Medium: {sum(1 for s in scored_iocs if s.severity_label == 'Medium')} | "
                f"Low: {sum(1 for s in scored_iocs if s.severity_label == 'Low')}")

    return scored_iocs


def _calculate_recency_days(timestamp_str: str, reference_time: datetime) -> float:
    """Calculate days between IOC timestamp and reference time."""
    try:
        # Handle various timestamp formats
        for fmt in [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d",
        ]:
            try:
                ts = datetime.strptime(timestamp_str, fmt).replace(tzinfo=timezone.utc)
                delta = reference_time - ts
                return max(0, delta.total_seconds() / 86400)
            except ValueError:
                continue
        return 30.0  # Default if parsing fails
    except Exception:
        return 30.0


def _score_to_label(score: float) -> str:
    """Map composite risk score to severity label."""
    if score >= 0.8:
        return "Critical"
    elif score >= 0.6:
        return "High"
    elif score >= 0.4:
        return "Medium"
    return "Low"


def get_risk_summary(scored_iocs: List[ScoredIOC]) -> dict:
    """Generate a summary of risk scoring results."""
    if not scored_iocs:
        return {"total": 0}

    return {
        "total": len(scored_iocs),
        "critical_count": sum(1 for s in scored_iocs if s.severity_label == "Critical"),
        "high_count": sum(1 for s in scored_iocs if s.severity_label == "High"),
        "medium_count": sum(1 for s in scored_iocs if s.severity_label == "Medium"),
        "low_count": sum(1 for s in scored_iocs if s.severity_label == "Low"),
        "top_5": [
            {"value": s.value, "type": s.ioc_type, "score": round(s.risk_score, 3),
             "actor": s.actor, "sightings": s.sightings}
            for s in scored_iocs[:5]
        ],
        "average_score": round(sum(s.risk_score for s in scored_iocs) / len(scored_iocs), 3),
        "actors_involved": list(set(s.actor for s in scored_iocs if s.actor != "Unknown")),
    }
