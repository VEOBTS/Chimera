from shared.logger import get_logger
from shared.utils import list_sample_files
from config import SAMPLES_DIR
 
from polymorphic.entropy_scanner import is_likely_packed
from polymorphic.decryptor_stub_scanner import scan_for_decryptor_stub
from metamorphic.opcode_graph import build_control_flow_graph
from metamorphic.cfg_structural_analysis import is_structurally_suspicious
 
logger = get_logger("main")
 
def run_polymorphic_checks(file_path):
    """Runs the static polymorphic checks that do not require angr."""
    packed, ratio = is_likely_packed(file_path)
    stub_found, stub_spots = scan_for_decryptor_stub(file_path)
    return {
        "likely_packed": packed,
        "high_entropy_ratio": round(ratio, 3),
        "decryptor_stub_found": stub_found,
        "decryptor_stub_locations": stub_spots,
    }
 
def run_metamorphic_checks(file_path):
    """Runs the structural metamorphic checks based on the control flow graph."""
    graph = build_control_flow_graph(file_path)
    suspicious, density, dead_end_ratio = is_structurally_suspicious(graph)
    return {
        "structurally_suspicious": suspicious,
        "branch_density": round(density, 3),
        "dead_end_ratio": round(dead_end_ratio, 3),
    }
 
def analyze_sample(file_path):
    logger.info(f"Analyzing: {file_path}")
    result = {"file": file_path}
    result.update(run_polymorphic_checks(file_path))
    result.update(run_metamorphic_checks(file_path))
    return result
 
def main():
    sample_files = list_sample_files(SAMPLES_DIR)
    if not sample_files:
        logger.info("No sample files found. Place files inside the samples folder first.")
        return
 
    for file_path in sample_files:
        result = analyze_sample(file_path)
        print(result)
 
if __name__ == "__main__":
    main()