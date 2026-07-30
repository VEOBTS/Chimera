import math
import os
from collections import Counter
 
def calculate_entropy(data_bytes):
    """
    Calculates the Shannon entropy of a chunk of bytes.
    Entropy is a number between 0 and 8 for byte data.
    A low number means the data is predictable, like normal code or text.
    A high number close to 8 means the data looks random,
    which is typical of encrypted or packed content.
    """
    if not data_bytes:
        return 0.0
 
    byte_counts = Counter(data_bytes)
    total_bytes = len(data_bytes)
    entropy = 0.0
 
    for count in byte_counts.values():
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)
 
    return entropy
 
def read_file_bytes(file_path):
    """Reads a file from disk and returns its raw bytes."""
    with open(file_path, "rb") as f:
        return f.read()
 
def list_sample_files(samples_dir):
    """Returns a list of full file paths for every file inside the samples folder."""
    if not os.path.isdir(samples_dir):
        return []
    return [
        os.path.join(samples_dir, name)
        for name in os.listdir(samples_dir)
        if os.path.isfile(os.path.join(samples_dir, name))
    ]