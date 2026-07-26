import networkx as nx
import networkx.algorithms.isomorphism as iso
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
from matplotlib.lines import Line2D
from io import BytesIO

def check_graph_threats(G):
    """
    Checks if the Code Graph matches known malicious templates (Signature-less).
    """
    threats = []
    
    # Template 1: Logic Bomb (Central node triggers multiple leaf nodes)
    # 0 -> 1, 0 -> 2, 0 -> 3 (Fan-out)
    Template_LogicBomb = nx.DiGraph()
    Template_LogicBomb.add_edges_from([(0,1), (0,2), (0,3)])
    
    GM = iso.DiGraphMatcher(G, Template_LogicBomb)
    if GM.subgraph_is_isomorphic():
        threats.append("Logic Bomb Template (Graph Isomorphism)")
        
    return threats

def plot_quantum_risk_graph(blocks, quantum_scores, entangled_pairs=None, anomaly_scores=None, title="Quantum Logic/Risk Graph", streamlit_buf=False):
    """
    blocks: List of logic blocks (dict, must have 'condition', 'calls')
    quantum_scores: List of quantum risk scores (0-1) for each block
    entangled_pairs: Optional list of (idx1, idx2) pairs to connect
    anomaly_scores: Optional list (same length as blocks) with anomaly scores
    streamlit_buf: If True, returns BytesIO buffer for Streamlit; else plt.show()
    """
    G = nx.DiGraph()
    for idx, block in enumerate(blocks):
        label = block['condition'][:30] + ("..." if len(block['condition']) > 30 else "")
        q_score = quantum_scores[idx]
        a_score = anomaly_scores[idx] if anomaly_scores is not None else 0
        # Risk coloring: black = max danger, red = high, yellow = mod, green = low
        color = (
            "#000" if q_score >= 0.92 else
            "#e74c3c" if q_score > 0.7 or a_score < -0.3 else
            "#f1c40f" if q_score > 0.3 else
            "#2ecc71"
        )
        G.add_node(idx, label=label, quantum_score=q_score, color=color)
        for call in block['calls']:
            for tgt_idx, blk in enumerate(blocks):
                if call in "".join(blk['body']):
                    G.add_edge(idx, tgt_idx, weight=1, style="solid")

    # Entanglement/chain
    if entangled_pairs:
        for i, j in entangled_pairs:
            G.add_edge(i, j, weight=2, style="dashed")

    pos = nx.spring_layout(G, seed=44)
    node_colors = [G.nodes[n]['color'] for n in G.nodes()]
    node_sizes = [500 + 2000*G.nodes[n]['quantum_score'] for n in G.nodes()]
    labels = {n: G.nodes[n]['label'] for n in G.nodes()}

    # Edge styles (dashed for entangled, solid for normal, thick for chained)
    edge_styles = []
    for u, v, d in G.edges(data=True):
        style = d.get('style', "solid")
        if style == "dashed":
            edge_styles.append((u, v, "dashed", 2.5))
        else:
            edge_styles.append((u, v, "solid", 1.0))

    plt.figure(figsize=(10,6))
    # Draw edges by style
    for u, v, style, width in edge_styles:
        nx.draw_networkx_edges(
            G, pos,
            edgelist=[(u, v)],
            width=width*2,
            edge_color="#34495e" if style == "solid" else "#9b59b6",
            style=style,
            arrows=True
        )

    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes, alpha=0.88)
    nx.draw_networkx_labels(G, pos, labels=labels, font_size=10, font_color="white")
    plt.title(title, fontsize=15)
    plt.axis("off")

    # Add risk legend
    legend_elements = [
        Patch(facecolor='#000', label='Max Danger (Quantum Kill)'),
        Patch(facecolor='#e74c3c', label='High Quantum Risk'),
        Patch(facecolor='#f1c40f', label='Moderate Risk'),
        Patch(facecolor='#2ecc71', label='Low/Green'),
        Line2D([0], [0], color="#34495e", lw=2, label='Normal Logic'),
        Line2D([0], [0], color="#9b59b6", lw=2, linestyle="--", label='Entanglement/Chain')
    ]
    plt.legend(handles=legend_elements, loc="upper left", frameon=True, fontsize=9)

    plt.tight_layout()
    if streamlit_buf:
        buf = BytesIO()
        plt.savefig(buf, format="png")
        buf.seek(0)
        plt.close()
        return buf
    else:
        plt.show()

# -------- DEMO ----------
if __name__ == "__main__":
    demo_blocks = [
        {"condition": "random.random() < 0.19", "calls": ["quantum_bomb"], "body": ["quantum_bomb()"]},
        {"condition": "user_input == secret", "calls": ["grant_access"], "body": ["grant_access()"]},
        {"condition": "seed(x) == 42", "calls": [], "body": ["shutdown()"]},
        {"condition": "quantum_check(y)", "calls": ["rare_chain"], "body": ["rare_chain()"]}
    ]
    quantum_scores = [0.97, 0.12, 0.71, 0.43]
    anomaly_scores = [-0.45, 0.13, -0.33, -0.07]
    entangled_pairs = [(0,2), (2,3)]

    plot_quantum_risk_graph(
        demo_blocks,
        quantum_scores,
        entangled_pairs=entangled_pairs,
        anomaly_scores=anomaly_scores,
        title="Advanced Quantum Risk & Entanglement Graph"
    )
