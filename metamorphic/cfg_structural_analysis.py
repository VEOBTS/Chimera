import sys
import os
import networkx as nx
 
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
from shared.logger import get_logger
from config import CFG_BRANCH_DENSITY_THRESHOLD
 
logger = get_logger("cfg_structural_analysis")
 
def calculate_branch_density(graph):
    """
    Branch density is the ratio of edges to nodes in the control flow graph.
    A normal, simply structured program has a ratio close to 1.
    A heavily obfuscated program tends to have many more edges than nodes,
    because obfuscation techniques add extra jumps and decision points.
    """
    node_count = graph.number_of_nodes()
    if node_count == 0:
        return 0.0
    return graph.number_of_edges() / node_count
 
def find_dead_end_blocks(graph):
    """
    Finds nodes that have incoming edges but no outgoing edges, other than the
    program's true exit points. A high number of these can indicate dead code
    inserted purely to confuse analysis, since real dead code blocks often
    do not connect anywhere meaningful.
    """
    dead_ends = [
        node for node in graph.nodes()
        if graph.out_degree(node) == 0 and graph.in_degree(node) > 0
    ]
    return dead_ends
 
def is_structurally_suspicious(graph):
    """
    Combines branch density with a check on dead end blocks to decide
    if a control flow graph looks structurally obfuscated on its own,
    with no comparison to any known malware sample required.
    """
    density = calculate_branch_density(graph)
    dead_ends = find_dead_end_blocks(graph)
    dead_end_ratio = len(dead_ends) / max(1, graph.number_of_nodes())
 
    suspicious = density >= CFG_BRANCH_DENSITY_THRESHOLD or dead_end_ratio >= 0.2
    logger.info(f"density={round(density, 3)}, dead_end_ratio={round(dead_end_ratio, 3)}, "
                f"suspicious={suspicious}")
    return suspicious, density, dead_end_ratio