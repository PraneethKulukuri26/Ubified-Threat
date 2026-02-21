"""
LLM Campaign Summarizer
=========================
Uses Groq LLM API to generate natural language threat campaign summaries.
Falls back to template-based summaries if no API key is configured.
"""

import os
import json
import logging
from typing import List, Dict, Optional
from pathlib import Path

from .ingestion import IOC, STIXParser
from .scoring import ScoredIOC

logger = logging.getLogger(__name__)


def generate_summary(
    scored_iocs: List[ScoredIOC],
    parser: STIXParser,
    enrichment_summary: dict,
    config: dict = None
) -> str:
    """
    Generate a threat campaign summary.

    Tries Groq LLM first; falls back to template-based summary.
    Returns markdown-formatted summary string.
    """
    if config is None:
        config = {}

    llm_config = config.get('llm', {})
    provider = llm_config.get('provider', 'groq')

    if provider == 'none':
        logger.info("LLM provider set to 'none', using template summary")
        return _template_summary(scored_iocs, parser, enrichment_summary)

    api_key = os.environ.get('GROQ_API_KEY', '')

    if not api_key:
        logger.warning("GROQ_API_KEY not set. Falling back to template summary.")
        return _template_summary(scored_iocs, parser, enrichment_summary)

    try:
        return _groq_summary(scored_iocs, parser, enrichment_summary, api_key, llm_config)
    except Exception as e:
        logger.error(f"LLM summarization failed: {e}. Falling back to template.")
        return _template_summary(scored_iocs, parser, enrichment_summary)


def _groq_summary(
    scored_iocs: List[ScoredIOC],
    parser: STIXParser,
    enrichment_summary: dict,
    api_key: str,
    llm_config: dict
) -> str:
    """Generate summary using Groq LLM."""
    from groq import Groq

    client = Groq(api_key=api_key)
    model = llm_config.get('model', 'llama-3.3-70b-versatile')
    max_tokens = llm_config.get('max_tokens', 2048)

    # Build context prompt
    prompt = _build_prompt(scored_iocs, parser, enrichment_summary)

    logger.info(f"Sending summarization request to Groq ({model})")

    response = client.chat.completions.create(
        model=model,
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a senior threat intelligence analyst. Generate a comprehensive, "
                    "actionable threat campaign summary based on the provided threat intelligence data. "
                    "Use markdown formatting. Include:\n"
                    "1. Executive Summary\n"
                    "2. Campaign Overview per threat actor\n"
                    "3. Key IOCs and their risk levels\n"
                    "4. MITRE ATT&CK TTPs observed\n"
                    "5. Affected infrastructure\n"
                    "6. Recommended Actions\n"
                    "Be specific, cite IOC values, and prioritize by risk."
                )
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        max_tokens=max_tokens,
        temperature=0.3,
    )

    summary = response.choices[0].message.content
    logger.info("LLM summary generated successfully")
    return summary


def _build_prompt(
    scored_iocs: List[ScoredIOC],
    parser: STIXParser,
    enrichment_summary: dict
) -> str:
    """Build the context prompt for the LLM."""
    sections = []

    # Threat actors
    sections.append("## Threat Actors Identified")
    for actor in parser.actors.values():
        sections.append(f"- **{actor.name}**: {actor.description}")
        if actor.aliases:
            sections.append(f"  Aliases: {', '.join(actor.aliases)}")
        sections.append(f"  Sophistication: {actor.sophistication} | Motivation: {actor.motivation}")

    # Malware
    sections.append("\n## Malware Families")
    for mal in parser.malware.values():
        sections.append(f"- **{mal.name}**: {mal.description}")
        if mal.malware_types:
            sections.append(f"  Types: {', '.join(mal.malware_types)}")

    # Top IOCs by risk
    sections.append("\n## Top Risk-Ranked IOCs")
    for ioc in scored_iocs[:15]:  # Top 15
        sections.append(
            f"- [{ioc.severity_label}] {ioc.ioc_type}: `{ioc.value}` "
            f"(Score: {ioc.risk_score:.3f}, Actor: {ioc.actor}, "
            f"Sightings: {ioc.sightings})"
        )

    # TTPs
    sections.append("\n## MITRE ATT&CK Techniques")
    for ap in parser.attack_patterns.values():
        sections.append(f"- **{ap.mitre_id}** - {ap.name}: {ap.description}")

    # SIEM Alert Summary
    sections.append("\n## SIEM Alert Summary")
    sections.append(f"- Total alerts matched: {enrichment_summary.get('total_alerts', 0)}")
    sections.append(f"- Unique IOCs seen: {enrichment_summary.get('unique_iocs', 0)}")
    sections.append(f"- Affected hosts: {', '.join(enrichment_summary.get('affected_hosts', []))}")

    severity_dist = enrichment_summary.get('severity_distribution', {})
    if severity_dist:
        sections.append(f"- Severity distribution: {json.dumps(severity_dist)}")

    return "\n".join(sections)


def _template_summary(
    scored_iocs: List[ScoredIOC],
    parser: STIXParser,
    enrichment_summary: dict
) -> str:
    """Generate a template-based summary (no LLM required)."""
    lines = []

    lines.append("# Threat Intelligence Campaign Summary")
    lines.append(f"\n*Generated by Unified Threat Intelligence & SIEM Fusion System*\n")

    # Executive Summary
    lines.append("## Executive Summary\n")
    actor_names = [a.name for a in parser.actors.values()]
    malware_names = [m.name for m in parser.malware.values()]
    critical_count = sum(1 for s in scored_iocs if s.severity_label == "Critical")
    high_count = sum(1 for s in scored_iocs if s.severity_label == "High")
    total_alerts = enrichment_summary.get('total_alerts', 0)

    lines.append(
        f"Analysis identified **{len(scored_iocs)} indicators of compromise** across "
        f"**{len(actor_names)} threat actor(s)** ({', '.join(actor_names) if actor_names else 'Unknown'}). "
        f"**{critical_count} critical** and **{high_count} high** severity IOCs were detected. "
        f"A total of **{total_alerts} SIEM alerts** matched known threat indicators."
    )

    # Per-actor breakdown
    lines.append("\n## Campaign Details\n")
    for actor in parser.actors.values():
        lines.append(f"### {actor.name}")
        lines.append(f"\n{actor.description}\n")
        if actor.aliases:
            lines.append(f"- **Aliases**: {', '.join(actor.aliases)}")
        lines.append(f"- **Sophistication**: {actor.sophistication}")
        lines.append(f"- **Motivation**: {actor.motivation}")

        # IOCs attributed to this actor
        actor_iocs = [s for s in scored_iocs if s.actor == actor.name]
        if actor_iocs:
            lines.append(f"\n**Associated IOCs** ({len(actor_iocs)}):\n")
            lines.append("| Type | Value | Risk Score | Sightings |")
            lines.append("|------|-------|------------|-----------|")
            for ioc in actor_iocs:
                display_val = ioc.value if len(ioc.value) <= 30 else ioc.value[:27] + "..."
                lines.append(
                    f"| {ioc.ioc_type} | `{display_val}` | "
                    f"{ioc.risk_score:.3f} ({ioc.severity_label}) | {ioc.sightings} |"
                )
        lines.append("")

    # Malware Families
    lines.append("## Malware Families\n")
    for mal in parser.malware.values():
        lines.append(f"- **{mal.name}**: {mal.description}")
        if mal.malware_types:
            lines.append(f"  - Types: {', '.join(mal.malware_types)}")

    # MITRE ATT&CK
    lines.append("\n## MITRE ATT&CK TTPs\n")
    lines.append("| Technique ID | Name | Description |")
    lines.append("|-------------|------|-------------|")
    for ap in parser.attack_patterns.values():
        lines.append(f"| {ap.mitre_id} | {ap.name} | {ap.description} |")

    # Affected Infrastructure
    lines.append("\n## Affected Infrastructure\n")
    hosts = enrichment_summary.get('affected_hosts', [])
    if hosts:
        lines.append(f"**Compromised/targeted hosts**: {', '.join(hosts)}")
    top_targets = enrichment_summary.get('top_targeted_ips', {})
    if top_targets:
        lines.append("\n**Most targeted external IPs**:\n")
        for ip, count in top_targets.items():
            lines.append(f"- `{ip}`: {count} connections")

    # Recommendations
    lines.append("\n## Recommended Actions\n")
    lines.append("1. **Immediate**: Block all Critical/High severity IOCs at firewall/proxy")
    lines.append("2. **Investigate**: Forensic analysis on affected hosts: " +
                 ", ".join(hosts[:5]) if hosts else "2. **Investigate**: Check all internal hosts")
    lines.append("3. **Hunt**: Execute the auto-generated SIEM queries to find additional activity")
    lines.append("4. **Patch**: Review and apply patches related to MITRE ATT&CK TTPs identified")
    lines.append("5. **Monitor**: Set up continuous monitoring for all IOCs listed above")

    return "\n".join(lines)


def save_summary(summary: str, output_path: str):
    """Save the summary to a markdown file."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(summary)
    logger.info(f"Threat summary saved to {output_path}")
