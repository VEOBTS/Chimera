import sys
import os
 
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
from shared.utils import calculate_entropy, read_file_bytes
from shared.logger import get_logger
from config import ENTROPY_THRESHOLD
 
logger = get_logger("entropy_scanner")
 
CHUNK_SIZE = 256  # bytes per chunk analyzed
 
def scan_file_entropy(file_path):
    """
    Splits the file into fixed size chunks and calculates entropy for each chunk.
    Returns a list of chunks whose entropy crossed the configured threshold,
    along with the entropy score for each flagged chunk.
    """
    data = read_file_bytes(file_path)
    flagged_chunks = []
 
    for offset in range(0, len(data), CHUNK_SIZE):
        chunk = data[offset:offset + CHUNK_SIZE]
        score = calculate_entropy(chunk)
        if score >= ENTROPY_THRESHOLD:
            flagged_chunks.append({"offset": offset, "entropy": round(score, 3)})
 
    logger.info(f"{file_path}: {len(flagged_chunks)} high-entropy chunk(s) found")
    return flagged_chunks
 
def is_likely_packed(file_path, flag_ratio_threshold=0.15):
    """
    Decides if a file is likely packed or encrypted.
    If more than the given ratio of chunks are flagged as high entropy,
    the whole file is treated as suspicious.
    """
    data = read_file_bytes(file_path)
    total_chunks = max(1, len(data) // CHUNK_SIZE)
    flagged = scan_file_entropy(file_path)
    ratio = len(flagged) / total_chunks
    return  ratio >= flag_ratio_threshold, ratio