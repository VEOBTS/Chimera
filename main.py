from shared.logger import get_logger
from shared.utils import list_sample_files
from config import SAMPLES_DIR
from config import SAMPLES_DIR, HMM_LOG_LIKELIHOOD_THRESHOLD
from polymorphic.entropy_scanner import is_likely_packed
from polymorphic.decryptor_stub_scanner import scan_for_decryptor_stub
from metamorphic.opcode_graph import build_control_flow_graph
from metamorphic.cfg_structural_analysis import is_structurally_suspicious

from shared.model_storage import load_model
from shared.syscall_tracer import trace_syscalls
from polymorphic.api_sequence_model import build_ngram_vector, score_sequence
from metamorphic.hmm_behavior import instructions_to_category_sequence, score_behavior_sequence
from metamorphic.sandbox_isolation import monitor_process, flag_dangerous_behavior
from shared.utils import disassemble_file


try:
    isolation_forest_model = load_model("isolation_forest_model")
    api_vocabulary = load_model("api_vocabulary")
except FileNotFoundError:
    isolation_forest_model = None
    api_vocabulary = None
    logger.info("Isolation Forest model not found. Run train_models.py first.")

try:
    hmm_model = load_model("hmm_behavior_model")
except FileNotFoundError:
    hmm_model = None
    logger.info("HMM model not found. Run train_models.py first.")
 
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
    result.update(run_isolation_forest_check(file_path))
    result.update(run_hmm_check(file_path))

    # Only run the sandbox on files already flagged by a static or ML check
    already_suspicious = any([
        result.get("likely_packed"),
        result.get("decryptor_stub_found"),
        result.get("structurally_suspicious"),
        result.get("isolation_forest_anomalous"),
        result.get("hmm_anomalous"),
    ])

    if already_suspicious:
        observations = monitor_process(file_path)
        dangerous, max_files, max_conns = flag_dangerous_behavior(observations)
        result["sandbox_confirmed_dangerous"] = dangerous
    else:
        result["sandbox_confirmed_dangerous"] = None

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

def run_isolation_forest_check(file_path):
    if isolation_forest_model is None or api_vocabulary is None:
        return {"isolation_forest_anomalous": None}

    calls = trace_syscalls(file_path)
    if len(calls) < 5:
        return {"isolation_forest_anomalous": None}

    vector = build_ngram_vector(calls, api_vocabulary)
    is_anomalous, raw_score = score_sequence(isolation_forest_model, vector)
    return {
        "isolation_forest_anomalous": is_anomalous,
        "isolation_forest_score": round(float(raw_score), 4),
    }

def run_hmm_check(file_path):
    if hmm_model is None:
        return {"hmm_anomalous": None}

    instructions = disassemble_file(file_path)
    categories = instructions_to_category_sequence(instructions)
    if len(categories) < 10:
        return {"hmm_anomalous": None}

    log_likelihood = score_behavior_sequence(hmm_model, categories)
    is_anomalous = log_likelihood < HMM_LOG_LIKELIHOOD_THRESHOLD
    return {
        "hmm_anomalous": is_anomalous,
        "hmm_log_likelihood": round(float(log_likelihood), 3),
    }