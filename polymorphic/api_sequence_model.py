import sys
import os
import numpy as np
from sklearn.ensemble import IsolationForest
 
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
from shared.logger import get_logger
from config import ISOLATION_FOREST_CONTAMINATION
 
logger = get_logger("api_sequence_model")
 
def build_ngram_vector(api_call_sequence, vocabulary, n=2):
    """
    Converts a sequence of API call names into a numeric vector,
    by counting how often each pair of consecutive calls (a 2-gram) appears.
    The vocabulary list fixes the vector's order and length across samples.
    """
    ngram_counts = {pair: 0 for pair in vocabulary}
    for i in range(len(api_call_sequence) - (n - 1)):
        pair = tuple(api_call_sequence[i:i + n])
        if pair in ngram_counts:
            ngram_counts[pair] += 1
    return np.array(list(ngram_counts.values()))
 
def train_isolation_forest(training_vectors):
    """
    Trains an Isolation Forest model on a set of normal API sequence vectors.
    Returns the trained model, ready to score new samples.
    """
    model = IsolationForest(
        contamination=ISOLATION_FOREST_CONTAMINATION,
        random_state=42
    )
    model.fit(training_vectors)
    logger.info(f"Isolation Forest trained on {len(training_vectors)} sequence(s)")
    return model
 
def score_sequence(model, vector):
    """
    Scores one new API call sequence against the trained model.
    Returns True if it is flagged as anomalous, along with the raw anomaly score.
    A more negative score means more anomalous.
    """
    prediction = model.predict([vector])[0]   #  1 = normal, -1 = anomaly
    raw_score = model.decision_function([vector])[0]
    is_anomalous = prediction == -1
    logger.info(f"Sequence scored: anomalous={is_anomalous}, raw_score={round(raw_score, 4)}")
    return is_anomalous, raw_score