import sys
import os
import numpy as np
from hmmlearn import hmm
 
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
from shared.logger import get_logger
from config import HMM_HIDDEN_STATES
 
logger = get_logger("hmm_behavior")
 
INSTRUCTION_CATEGORIES = {
    "arithmetic": 0, "memory": 1, "control_transfer": 2, "logic": 3, "other": 4
}
 
def categorize_instruction(mnemonic):
    """Maps a raw instruction mnemonic to a small, fixed set of behavior categories."""
    arithmetic_ops = {"add", "sub", "mul", "div", "inc", "dec"}
    memory_ops = {"mov", "push", "pop", "lea"}
    control_ops = {"jmp", "je", "jne", "call", "ret", "jz", "jnz"}
    logic_ops = {"xor", "and", "or", "not", "shl", "shr"}
 
    if mnemonic in arithmetic_ops:
        return "arithmetic"
    if mnemonic in memory_ops:
        return "memory"
    if mnemonic in control_ops:
        return "control_transfer"
    if mnemonic in logic_ops:
        return "logic"
    return "other"
 
def instructions_to_category_sequence(instructions):
    """Converts a list of Capstone instructions into a list of category numbers."""
    return [
        INSTRUCTION_CATEGORIES[categorize_instruction(instr.mnemonic)]
        for instr in instructions
    ]
 
def train_hmm(category_sequences):
    """
    Trains a Hidden Markov Model on a list of category sequences from known,
    trusted, non-malicious programs. This establishes what a normal
    behavior pattern looks like.
    """
    lengths = [len(seq) for seq in category_sequences]
    combined = np.concatenate(category_sequences).reshape(-1, 1)
 
    model = hmm.CategoricalHMM(n_components=HMM_HIDDEN_STATES, random_state=42)
    model.fit(combined, lengths)
    logger.info(f"HMM trained on {len(category_sequences)} sequence(s)")
    return model
 
def score_behavior_sequence(model, category_sequence):
    """
    Scores one new category sequence against the trained HMM.
    Returns the log-likelihood score. A much lower score than the training
    average means this sequence behaves unlike normal software.
    """
    sequence = np.array(category_sequence).reshape(-1, 1)
    log_likelihood = model.score(sequence)
    logger.info(f"Sequence log-likelihood: {round(log_likelihood, 3)}")
    return log_likelihood