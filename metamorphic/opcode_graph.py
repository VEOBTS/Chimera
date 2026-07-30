import sys
import os
import angr
import networkx as nx
 
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
from shared.logger import get_logger
 
logger = get_logger("opcode_graph")
 
def build_control_flow_graph(file_path):
    """
    Loads a binary with angr and extracts its control flow graph.
    Returns a NetworkX directed graph, where each node is a code block address
    and each edge represents a possible jump between blocks.
    """
    project = angr.Project(file_path, auto_load_libs=False)
    cfg = project.analyses.CFGFast()
 
    graph = nx.DiGraph()
    for node in cfg.graph.nodes():
        graph.add_node(node.addr)
    for source, destination in cfg.graph.edges():
        graph.add_edge(source.addr, destination.addr)
 
    logger.info(f"{file_path}: CFG built with {graph.number_of_nodes()} node(s), "
                f"{graph.number_of_edges()} edge(s)")
    return graph
 
def graph_similarity_score(graph_a, graph_b):
    """
    Compares two control flow graphs and returns a similarity score between 0 and 1.
    A score of 1 means identical structure. A score of 0 means completely different.
    This uses graph edit distance on smaller graphs, since it is exact but slow.
    """
    max_possible_edits = graph_a.number_of_edges() + graph_b.number_of_edges()
    if max_possible_edits == 0:
        return 1.0
 
    edit_distance = nx.graph_edit_distance(graph_a, graph_b, timeout=30)
    if edit_distance is None:
        return 0.0
 
    similarity = 1 - (edit_distance / max_possible_edits)
    return max(0.0, similarity)