import logging
import os
 
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "detection_system.log")
 
def get_logger(name):
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
 
    formatter = logging.Formatter(
        "%(asctime)s | %(name)s | %(levelname)s | %(message)s"
    )
 
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(formatter)
 
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
 
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger