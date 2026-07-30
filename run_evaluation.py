import os
import csv
from shared.logger import get_logger
from main import analyze_sample
 
logger = get_logger("run_evaluation")
 
TEST_SAMPLES_DIR = "test_samples"
LABELS_FILE = "test_labels.txt"
RESULTS_FILE = "logs/evaluation_results.csv"
 
def load_labels():
    labels = {}
    with open(LABELS_FILE) as f:
        for line in f:
            name, label = line.strip().split(",")
            labels[name] = label
    return labels
 
def run_evaluation():
    labels = load_labels()
    rows = []
 
    for file_name in os.listdir(TEST_SAMPLES_DIR):
        file_path = os.path.join(TEST_SAMPLES_DIR, file_name)
        true_label = labels.get(file_name, "unknown")
 
        result = analyze_sample(file_path)
        predicted_flagged = (
            result.get("likely_packed")
            or result.get("decryptor_stub_found")
            or result.get("structurally_suspicious")
            or result.get("isolation_forest_anomalous")
            or result.get("hmm_anomalous")
            or result.get("sandbox_confirmed_dangerous")
        )
        predicted_label = "malicious" if predicted_flagged else "clean"
 
        rows.append({
            "file": file_name,
            "true_label": true_label,
            "predicted_label": predicted_label,
            "correct": true_label == predicted_label,
        })
        logger.info(f"{file_name}: true={true_label}, predicted={predicted_label}")
 
    with open(RESULTS_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["file", "true_label", "predicted_label", "correct"])
        writer.writeheader()
        writer.writerows(rows)
 
    accuracy = sum(r["correct"] for r in rows) / len(rows) if rows else 0
    logger.info(f"Evaluation complete. Accuracy: {round(accuracy * 100, 2)}%")
    print(f"Accuracy: {round(accuracy * 100, 2)}% over {len(rows)} sample(s)")
 
if __name__ == "__main__":
    run_evaluation()