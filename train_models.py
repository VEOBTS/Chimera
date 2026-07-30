import os
from shared.logger import get_logger
from shared.model_storage import save_model
from shared.utils import list_sample_files
from polymorphic.api_sequence_model import build_ngram_vector, train_isolation_forest
from metamorphic.hmm_behavior import instructions_to_category_sequence, train_hmm
from shared.utils import disassemble_file 
from shared.syscall_tracer import trace_syscalls
from polymorphic.api_sequence_model import build_ngram_vector, build_vocabulary, train_isolation_forest

logger = get_logger("train_models")
 
CLEAN_SET_DIR = os.path.expanduser("~/clean_training_set")
 
def train_metamorphic_model():
    category_sequences = []
    for file_path in list_sample_files(CLEAN_SET_DIR):
        try:
            instructions = disassemble_file(file_path)
            categories = instructions_to_category_sequence(instructions)
            if len(categories) > 10:
                category_sequences.append(categories)
        except Exception as e:
            logger.info(f"Skipping {file_path}: {e}")
 
    model = train_hmm(category_sequences)
    save_model(model, "hmm_behavior_model")
    logger.info("Metamorphic HMM model saved.")
 
if __name__ == "__main__":
    train_metamorphic_model()
from shared.syscall_tracer import trace_syscalls
from polymorphic.api_sequence_model import build_ngram_vector, build_vocabulary, train_isolation_forest

def train_polymorphic_model():
    sequences = []
    for file_path in list_sample_files(CLEAN_SET_DIR):
        try:
            calls = trace_syscalls(file_path)
            if len(calls) > 5:
                sequences.append(calls)
        except Exception as e:
            logger.info(f"Skipping {file_path}: {e}")

    vocabulary = build_vocabulary(sequences)
    vectors = [build_ngram_vector(seq, vocabulary) for seq in sequences]

    model = train_isolation_forest(vectors)
    save_model(model, "isolation_forest_model")
    save_model(vocabulary, "api_vocabulary")
    logger.info("Polymorphic Isolation Forest model saved.")

if __name__ == "__main__":
    train_metamorphic_model()
    train_polymorphic_model()