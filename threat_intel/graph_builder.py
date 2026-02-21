"""
Attacker Infrastructure Graph Builder
=======================================
Builds and visualizes attacker infrastructure graphs from STIX relationships.
Exports as PNG (Matplotlib) and interactive HTML (Plotly).
"""

import logging
from typing import List, Dict, Optional
from pathlib import Path

import networkx as nx
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

from .ingestion import STIXParser, IOC

logger = logging.getLogger(__name__)

# Color scheme for node types
NODE_COLORS = {
    'threat-actor': '#e74c3c',    # Red
    'malware': '#e67e22',          # Orange
    'indicator-ip': '#3498db',     # Blue
    'indicator-domain': '#2ecc71', # Green
    'indicator-hash': '#9b59b6',   # Purple
    'attack-pattern': '#f39c12',   # Yellow
    'unknown': '#95a5a6',          # Gray
}

NODE_SHAPES = {
    'threat-actor': 's',     # Square
    'malware': 'D',          # Diamond
    'indicator-ip': 'o',     # Circle
    'indicator-domain': 'o', # Circle
    'indicator-hash': 'o',   # Circle
    'attack-pattern': '^',   # Triangle
}


def build_threat_graph(parser: STIXParser, scored_iocs: List = None) -> nx.DiGraph:
    """
    Build a directed graph from STIX objects and relationships.

    Nodes: Threat actors, malware, indicators (IOCs), attack patterns
    Edges: STIX relationships (uses, indicates, etc.)
    """
    G = nx.DiGraph()

    # Add threat actor nodes
    for actor_id, actor in parser.actors.items():
        G.add_node(actor.name, **{
            'node_type': 'threat-actor',
            'stix_id': actor_id,
            'description': actor.description,
            'sophistication': actor.sophistication,
            'motivation': actor.motivation,
            'aliases': ", ".join(actor.aliases),
        })

    # Add malware nodes
    for mal_id, mal in parser.malware.items():
        G.add_node(mal.name, **{
            'node_type': 'malware',
            'stix_id': mal_id,
            'description': mal.description,
            'malware_types': ", ".join(mal.malware_types),
        })

    # Add attack pattern nodes
    for ap_id, ap in parser.attack_patterns.items():
        label = f"{ap.name}\n({ap.mitre_id})" if ap.mitre_id else ap.name
        G.add_node(label, **{
            'node_type': 'attack-pattern',
            'stix_id': ap_id,
            'mitre_id': ap.mitre_id,
            'description': ap.description,
        })

    # Add IOC indicator nodes
    for ioc in parser.iocs:
        node_type = f"indicator-{ioc.ioc_type}" if ioc.ioc_type in ('ip', 'ipv4', 'domain', 'hash', 'sha256') else 'unknown'
        if ioc.ioc_type in ('ipv4', 'ipv6'):
            node_type = 'indicator-ip'
        elif ioc.ioc_type == 'domain':
            node_type = 'indicator-domain'
        elif ioc.ioc_type in ('sha256', 'md5', 'sha1'):
            node_type = 'indicator-hash'

        # Truncate long hash values for display
        display_name = ioc.value if len(ioc.value) <= 20 else ioc.value[:12] + "..."

        risk_score = 0.0
        if scored_iocs:
            for si in scored_iocs:
                if si.value == ioc.value:
                    risk_score = si.risk_score if hasattr(si, 'risk_score') else 0.0
                    break

        G.add_node(display_name, **{
            'node_type': node_type,
            'full_value': ioc.value,
            'ioc_type': ioc.ioc_type,
            'description': ioc.description,
            'labels': ", ".join(ioc.labels),
            'risk_score': risk_score,
        })

    # Add edges from relationships
    for rel in parser.relationships:
        source_name = _resolve_name(rel.source_ref, parser)
        target_name = _resolve_name(rel.target_ref, parser)

        if source_name and target_name:
            G.add_edge(source_name, target_name, **{
                'relationship': rel.relationship_type,
                'description': rel.description,
            })

    logger.info(f"Built threat graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return G


def _resolve_name(stix_id: str, parser: STIXParser) -> Optional[str]:
    """Resolve a STIX ID to a display name."""
    if stix_id in parser.actors:
        return parser.actors[stix_id].name
    if stix_id in parser.malware:
        return parser.malware[stix_id].name
    if stix_id in parser.attack_patterns:
        ap = parser.attack_patterns[stix_id]
        return f"{ap.name}\n({ap.mitre_id})" if ap.mitre_id else ap.name
    for ioc in parser.iocs:
        if ioc.stix_id == stix_id:
            return ioc.value if len(ioc.value) <= 20 else ioc.value[:12] + "..."
    return None


def export_graph_png(G: nx.DiGraph, output_path: str, title: str = "Attacker Infrastructure Graph"):
    """Export the threat graph as a PNG image using Matplotlib."""
    if G.number_of_nodes() == 0:
        logger.warning("Empty graph, skipping PNG export")
        return

    fig, ax = plt.subplots(1, 1, figsize=(16, 12))
    fig.patch.set_facecolor('#1a1a2e')
    ax.set_facecolor('#1a1a2e')

    # Layout
    pos = nx.spring_layout(G, k=2.5, iterations=60, seed=42)

    # Draw edges
    nx.draw_networkx_edges(
        G, pos, ax=ax,
        edge_color='#4a4a6a',
        arrows=True,
        arrowsize=15,
        width=1.5,
        alpha=0.7,
        connectionstyle="arc3,rad=0.1"
    )

    # Draw edge labels
    edge_labels = {(u, v): d.get('relationship', '') for u, v, d in G.edges(data=True)}
    nx.draw_networkx_edge_labels(
        G, pos, edge_labels=edge_labels, ax=ax,
        font_size=7, font_color='#8888aa',
        bbox=dict(boxstyle='round,pad=0.1', facecolor='#1a1a2e', edgecolor='none', alpha=0.8)
    )

    # Draw nodes by type
    for node_type, color in NODE_COLORS.items():
        nodelist = [n for n, d in G.nodes(data=True) if d.get('node_type') == node_type]
        if nodelist:
            sizes = []
            for n in nodelist:
                if node_type == 'threat-actor':
                    sizes.append(1200)
                elif node_type == 'malware':
                    sizes.append(900)
                elif node_type == 'attack-pattern':
                    sizes.append(700)
                else:
                    sizes.append(600)

            nx.draw_networkx_nodes(
                G, pos, nodelist=nodelist, ax=ax,
                node_color=color, node_size=sizes,
                alpha=0.9, edgecolors='white', linewidths=1.5
            )

    # Draw labels
    nx.draw_networkx_labels(
        G, pos, ax=ax,
        font_size=8, font_color='white', font_weight='bold'
    )

    # Legend
    legend_patches = [
        mpatches.Patch(color=NODE_COLORS['threat-actor'], label='Threat Actor'),
        mpatches.Patch(color=NODE_COLORS['malware'], label='Malware'),
        mpatches.Patch(color=NODE_COLORS['indicator-ip'], label='IP Address'),
        mpatches.Patch(color=NODE_COLORS['indicator-domain'], label='Domain'),
        mpatches.Patch(color=NODE_COLORS['indicator-hash'], label='File Hash'),
        mpatches.Patch(color=NODE_COLORS['attack-pattern'], label='ATT&CK TTP'),
    ]
    ax.legend(handles=legend_patches, loc='upper left', fontsize=9,
              facecolor='#16213e', edgecolor='#4a4a6a', labelcolor='white')

    ax.set_title(title, fontsize=16, color='white', fontweight='bold', pad=20)
    ax.axis('off')

    plt.tight_layout()
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path, dpi=150, bbox_inches='tight', facecolor=fig.get_facecolor())
    plt.close()

    logger.info(f"Graph exported to {output_path}")


def export_graph_html(G: nx.DiGraph, output_path: str, title: str = "Attacker Infrastructure Graph"):
    """Export the threat graph as an interactive HTML file using Plotly."""
    try:
        import plotly.graph_objects as go
    except ImportError:
        logger.error("Plotly not installed. Install: pip install plotly")
        return

    if G.number_of_nodes() == 0:
        logger.warning("Empty graph, skipping HTML export")
        return

    pos = nx.spring_layout(G, k=2.5, iterations=60, seed=42)

    # Edge traces
    edge_x, edge_y = [], []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1.5, color='#4a4a6a'),
        hoverinfo='none',
        mode='lines'
    )

    # Node traces grouped by type
    node_traces = []
    for node_type, color in NODE_COLORS.items():
        nodes = [(n, d) for n, d in G.nodes(data=True) if d.get('node_type') == node_type]
        if not nodes:
            continue

        node_x = [pos[n][0] for n, _ in nodes]
        node_y = [pos[n][1] for n, _ in nodes]
        texts = []
        for n, d in nodes:
            hover = f"<b>{n}</b><br>Type: {node_type}"
            if d.get('description'):
                hover += f"<br>{d['description'][:100]}"
            if d.get('risk_score', 0) > 0:
                hover += f"<br>Risk Score: {d['risk_score']:.3f}"
            texts.append(hover)

        size = 25 if node_type == 'threat-actor' else 20 if node_type == 'malware' else 15

        trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            hoverinfo='text',
            hovertext=texts,
            text=[n for n, _ in nodes],
            textposition="top center",
            textfont=dict(size=9, color='white'),
            name=node_type.replace('-', ' ').title(),
            marker=dict(size=size, color=color, line=dict(width=1.5, color='white'))
        )
        node_traces.append(trace)

    fig = go.Figure(
        data=[edge_trace] + node_traces,
        layout=go.Layout(
            title=dict(text=title, font=dict(size=18, color='white')),
            showlegend=True,
            hovermode='closest',
            plot_bgcolor='#1a1a2e',
            paper_bgcolor='#1a1a2e',
            font=dict(color='white'),
            legend=dict(bgcolor='#16213e', bordercolor='#4a4a6a'),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            margin=dict(l=20, r=20, t=60, b=20),
        )
    )

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    fig.write_html(output_path)
    logger.info(f"Interactive graph exported to {output_path}")
