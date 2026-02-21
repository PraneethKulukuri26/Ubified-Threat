"""
Threat Feed Ingestion Module
=============================
Handles ingestion from STIX/TAXII servers, local STIX bundles, and OSINT CSV/JSON feeds.
Normalizes all data into a unified IOC format.
"""

import json
import csv
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Optional, Any
from pathlib import Path
import re

logger = logging.getLogger(__name__)


@dataclass
class IOC:
    """Unified Indicator of Compromise data structure."""
    ioc_type: str           # ipv4, ipv6, domain, sha256, md5, url
    value: str              # The actual IOC value
    source: str             # Feed source name
    timestamp: str          # When the IOC was reported
    actor: str = "Unknown"  # Attributed threat actor
    ttp: str = ""           # MITRE ATT&CK TTP IDs
    confidence: str = "medium"  # low, medium, high, critical
    description: str = ""
    labels: List[str] = field(default_factory=list)
    campaign: str = ""
    malware_family: str = ""
    stix_id: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ThreatActor:
    """Threat actor extracted from STIX data."""
    stix_id: str
    name: str
    description: str = ""
    aliases: List[str] = field(default_factory=list)
    sophistication: str = ""
    motivation: str = ""


@dataclass
class Malware:
    """Malware object extracted from STIX data."""
    stix_id: str
    name: str
    description: str = ""
    malware_types: List[str] = field(default_factory=list)


@dataclass
class AttackPattern:
    """MITRE ATT&CK technique from STIX data."""
    stix_id: str
    name: str
    description: str = ""
    mitre_id: str = ""


@dataclass
class Relationship:
    """STIX relationship between objects."""
    source_ref: str
    target_ref: str
    relationship_type: str
    description: str = ""


class STIXParser:
    """Parses STIX 2.1 bundles into normalized IOC and relationship data."""

    # Regex patterns to extract IOC values from STIX patterns
    PATTERN_EXTRACTORS = {
        'ipv4': re.compile(r"ipv4-addr:value\s*=\s*'([^']+)'"),
        'ipv6': re.compile(r"ipv6-addr:value\s*=\s*'([^']+)'"),
        'domain': re.compile(r"domain-name:value\s*=\s*'([^']+)'"),
        'url': re.compile(r"url:value\s*=\s*'([^']+)'"),
        'sha256': re.compile(r"file:hashes\.'SHA-256'\s*=\s*'([^']+)'"),
        'md5': re.compile(r"file:hashes\.'MD5'\s*=\s*'([^']+)'"),
        'sha1': re.compile(r"file:hashes\.'SHA-1'\s*=\s*'([^']+)'"),
    }

    def __init__(self):
        self.actors: Dict[str, ThreatActor] = {}
        self.malware: Dict[str, Malware] = {}
        self.attack_patterns: Dict[str, AttackPattern] = {}
        self.relationships: List[Relationship] = []
        self.iocs: List[IOC] = []

    def parse_bundle(self, bundle_data: dict, source: str = "STIX") -> List[IOC]:
        """Parse a STIX 2.1 bundle and return list of IOCs."""
        objects = bundle_data.get("objects", [])

        # First pass: collect all context objects
        for obj in objects:
            obj_type = obj.get("type", "")
            if obj_type == "threat-actor":
                self._parse_actor(obj)
            elif obj_type == "malware":
                self._parse_malware(obj)
            elif obj_type == "attack-pattern":
                self._parse_attack_pattern(obj)
            elif obj_type == "relationship":
                self._parse_relationship(obj)

        # Second pass: parse indicators with full context
        for obj in objects:
            if obj.get("type") == "indicator":
                self._parse_indicator(obj, source)

        # Enrich IOCs with relationship context
        self._enrich_from_relationships()

        logger.info(f"Parsed {len(self.iocs)} IOCs, {len(self.actors)} actors, "
                    f"{len(self.malware)} malware, {len(self.relationships)} relationships")
        return self.iocs

    def _parse_actor(self, obj: dict):
        actor = ThreatActor(
            stix_id=obj["id"],
            name=obj.get("name", "Unknown"),
            description=obj.get("description", ""),
            aliases=obj.get("aliases", []),
            sophistication=obj.get("sophistication", ""),
            motivation=obj.get("primary_motivation", "")
        )
        self.actors[obj["id"]] = actor

    def _parse_malware(self, obj: dict):
        mal = Malware(
            stix_id=obj["id"],
            name=obj.get("name", "Unknown"),
            description=obj.get("description", ""),
            malware_types=obj.get("malware_types", [])
        )
        self.malware[obj["id"]] = mal

    def _parse_attack_pattern(self, obj: dict):
        mitre_id = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id", "")
                break
        ap = AttackPattern(
            stix_id=obj["id"],
            name=obj.get("name", "Unknown"),
            description=obj.get("description", ""),
            mitre_id=mitre_id
        )
        self.attack_patterns[obj["id"]] = ap

    def _parse_relationship(self, obj: dict):
        rel = Relationship(
            source_ref=obj.get("source_ref", ""),
            target_ref=obj.get("target_ref", ""),
            relationship_type=obj.get("relationship_type", ""),
            description=obj.get("description", "")
        )
        self.relationships.append(rel)

    def _parse_indicator(self, obj: dict, source: str):
        pattern = obj.get("pattern", "")
        ioc_type, value = self._extract_from_pattern(pattern)
        if not value:
            logger.warning(f"Could not extract IOC from pattern: {pattern}")
            return

        ioc = IOC(
            ioc_type=ioc_type,
            value=value,
            source=source,
            timestamp=obj.get("created", datetime.utcnow().isoformat()),
            description=obj.get("description", ""),
            labels=obj.get("labels", []),
            stix_id=obj.get("id", ""),
            confidence=self._map_confidence(obj.get("confidence", 50))
        )
        self.iocs.append(ioc)

    def _extract_from_pattern(self, pattern: str) -> tuple:
        """Extract IOC type and value from a STIX pattern string."""
        for ioc_type, regex in self.PATTERN_EXTRACTORS.items():
            match = regex.search(pattern)
            if match:
                return ioc_type, match.group(1)
        return "", ""

    def _map_confidence(self, confidence) -> str:
        """Map STIX confidence score to severity level."""
        if isinstance(confidence, str):
            return confidence
        if confidence >= 85:
            return "critical"
        elif confidence >= 65:
            return "high"
        elif confidence >= 35:
            return "medium"
        return "low"

    def _enrich_from_relationships(self):
        """Use relationships to add actor/malware/TTP context to IOCs."""
        # Build lookup: indicator_id -> [related objects]
        indicator_rels = {}
        actor_malware = {}  # malware_id -> actor_name
        actor_ttps = {}     # actor_id -> [ttp_ids]
        malware_indicators = {}  # indicator_id -> malware_id

        for rel in self.relationships:
            # Actor uses Malware
            if rel.relationship_type == "uses":
                if rel.source_ref.startswith("threat-actor") and rel.target_ref.startswith("malware"):
                    actor = self.actors.get(rel.source_ref)
                    if actor:
                        actor_malware[rel.target_ref] = actor.name
                # Actor uses AttackPattern
                elif rel.source_ref.startswith("threat-actor") and rel.target_ref.startswith("attack-pattern"):
                    ap = self.attack_patterns.get(rel.target_ref)
                    if ap:
                        actor_ttps.setdefault(rel.source_ref, []).append(ap.mitre_id)

            # Indicator indicates Malware/Actor
            elif rel.relationship_type == "indicates":
                if rel.source_ref.startswith("indicator"):
                    malware_indicators[rel.source_ref] = rel.target_ref

        # Enrich each IOC
        for ioc in self.iocs:
            target_ref = malware_indicators.get(ioc.stix_id, "")

            # If indicator -> malware, find actor who uses that malware
            if target_ref.startswith("malware"):
                mal = self.malware.get(target_ref)
                if mal:
                    ioc.malware_family = mal.name
                actor_name = actor_malware.get(target_ref, "")
                if actor_name:
                    ioc.actor = actor_name
                    # Find actor's TTPs
                    for actor_id, actor in self.actors.items():
                        if actor.name == actor_name:
                            ttps = actor_ttps.get(actor_id, [])
                            ioc.ttp = ", ".join(ttps)
                            break

            # If indicator -> actor directly
            elif target_ref.startswith("threat-actor"):
                actor = self.actors.get(target_ref)
                if actor:
                    ioc.actor = actor.name
                    ttps = actor_ttps.get(target_ref, [])
                    ioc.ttp = ", ".join(ttps)


class LocalSTIXIngester:
    """Ingest IOCs from local STIX bundle JSON files."""

    def __init__(self, file_paths: List[str]):
        self.file_paths = file_paths

    def ingest(self) -> tuple:
        """Returns (iocs, parser) tuple for access to full context."""
        all_iocs = []
        parser = STIXParser()

        for path in self.file_paths:
            p = Path(path)
            if not p.exists():
                logger.warning(f"STIX file not found: {path}")
                continue
            try:
                with open(p, 'r', encoding='utf-8') as f:
                    bundle = json.load(f)
                iocs = parser.parse_bundle(bundle, source=f"STIX:{p.name}")
                all_iocs.extend(iocs)
                logger.info(f"Loaded {len(iocs)} IOCs from {p.name}")
            except (json.JSONDecodeError, KeyError) as e:
                logger.error(f"Error parsing STIX file {path}: {e}")

        return all_iocs, parser


class OSINTIngester:
    """Ingest IOCs from CSV/JSON OSINT feeds."""

    def __init__(self, file_paths: List[str]):
        self.file_paths = file_paths

    def ingest(self) -> List[IOC]:
        all_iocs = []
        for path in self.file_paths:
            p = Path(path)
            if not p.exists():
                logger.warning(f"OSINT file not found: {path}")
                continue

            if p.suffix.lower() == '.csv':
                iocs = self._parse_csv(p)
            elif p.suffix.lower() == '.json':
                iocs = self._parse_json(p)
            else:
                logger.warning(f"Unsupported OSINT format: {p.suffix}")
                continue

            all_iocs.extend(iocs)
            logger.info(f"Loaded {len(iocs)} IOCs from OSINT feed: {p.name}")

        return all_iocs

    def _parse_csv(self, path: Path) -> List[IOC]:
        iocs = []
        with open(path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                ioc = IOC(
                    ioc_type=row.get('ioc_type', self._detect_type(row.get('ioc_value', ''))),
                    value=row.get('ioc_value', '').strip(),
                    source=row.get('source', f"OSINT:{path.name}"),
                    timestamp=row.get('last_seen', datetime.utcnow().isoformat()),
                    actor=row.get('actor', 'Unknown'),
                    confidence=row.get('confidence', 'medium'),
                    description=row.get('description', ''),
                )
                if ioc.value:
                    iocs.append(ioc)
        return iocs

    def _parse_json(self, path: Path) -> List[IOC]:
        iocs = []
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        items = data if isinstance(data, list) else data.get('indicators', data.get('data', []))
        for item in items:
            ioc = IOC(
                ioc_type=item.get('ioc_type', item.get('type', 'unknown')),
                value=item.get('ioc_value', item.get('value', item.get('indicator', ''))),
                source=item.get('source', f"OSINT:{path.name}"),
                timestamp=item.get('last_seen', item.get('timestamp', datetime.utcnow().isoformat())),
                actor=item.get('actor', 'Unknown'),
                confidence=item.get('confidence', 'medium'),
                description=item.get('description', ''),
            )
            if ioc.value:
                iocs.append(ioc)
        return iocs

    def _detect_type(self, value: str) -> str:
        """Auto-detect IOC type from value pattern."""
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', value):
            return 'ipv4'
        elif ':' in value and len(value) > 10:
            return 'ipv6'
        elif re.match(r'^[a-fA-F0-9]{64}$', value):
            return 'sha256'
        elif re.match(r'^[a-fA-F0-9]{32}$', value):
            return 'md5'
        elif '.' in value and not value.startswith('http'):
            return 'domain'
        elif value.startswith('http'):
            return 'url'
        return 'unknown'


class TAXIIIngester:
    """Ingest IOCs from a TAXII 2.0/2.1 server."""

    def __init__(self, server_configs: List[Dict]):
        self.server_configs = server_configs

    def ingest(self) -> tuple:
        """Returns (iocs, parser) tuple."""
        all_iocs = []
        parser = STIXParser()

        for config in self.server_configs:
            try:
                from taxii2client.v20 import Server as TAXIIServer, Collection
                url = config.get('url', '')
                logger.info(f"Connecting to TAXII server: {url}")

                server = TAXIIServer(url, user=config.get('username'), password=config.get('password'))
                api_root = server.api_roots[0] if server.api_roots else None
                if not api_root:
                    logger.warning(f"No API roots found at {url}")
                    continue

                collection_id = config.get('collection_id')
                if collection_id:
                    collection = Collection(
                        f"{api_root.url}collections/{collection_id}/",
                        user=config.get('username'),
                        password=config.get('password')
                    )
                    bundle = collection.get_objects()
                    iocs = parser.parse_bundle(bundle, source=f"TAXII:{url}")
                    all_iocs.extend(iocs)
                else:
                    for col in api_root.collections:
                        bundle = col.get_objects()
                        iocs = parser.parse_bundle(bundle, source=f"TAXII:{url}")
                        all_iocs.extend(iocs)

            except ImportError:
                logger.error("taxii2-client not installed. Install: pip install taxii2-client")
            except Exception as e:
                logger.error(f"Error connecting to TAXII server: {e}")

        return all_iocs, parser


def ingest_all_feeds(config: dict) -> tuple:
    """
    Master ingestion function. Ingests from all configured sources.
    Returns (all_iocs, stix_parser) tuple.
    """
    all_iocs = []
    stix_parser = STIXParser()

    # 1. Local STIX bundles
    local_stix = config.get('feeds', {}).get('local_stix', [])
    if local_stix:
        ingester = LocalSTIXIngester(local_stix)
        iocs, parser = ingester.ingest()
        all_iocs.extend(iocs)
        stix_parser = parser  # Use this parser for its context data

    # 2. OSINT feeds
    osint_feeds = config.get('feeds', {}).get('osint_feeds', [])
    if osint_feeds:
        ingester = OSINTIngester(osint_feeds)
        iocs = ingester.ingest()
        all_iocs.extend(iocs)

    # 3. TAXII servers
    taxii_servers = config.get('feeds', {}).get('taxii_servers', [])
    if taxii_servers:
        ingester = TAXIIIngester(taxii_servers)
        iocs, _ = ingester.ingest()
        all_iocs.extend(iocs)

    # Deduplicate by (type, value)
    seen = set()
    unique_iocs = []
    for ioc in all_iocs:
        key = (ioc.ioc_type, ioc.value)
        if key not in seen:
            seen.add(key)
            unique_iocs.append(ioc)
        else:
            # Merge: keep higher confidence
            for existing in unique_iocs:
                if (existing.ioc_type, existing.value) == key:
                    conf_rank = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
                    if conf_rank.get(ioc.confidence, 0) > conf_rank.get(existing.confidence, 0):
                        existing.confidence = ioc.confidence
                    if ioc.actor != "Unknown" and existing.actor == "Unknown":
                        existing.actor = ioc.actor
                    break

    logger.info(f"Total unique IOCs ingested: {len(unique_iocs)}")
    return unique_iocs, stix_parser
