import sys
import os
import time
import subprocess
import psutil
 
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
from shared.logger import get_logger
from config import SANDBOX_MONITOR_SECONDS
 
logger = get_logger("sandbox_isolation")
 
def monitor_process(file_path, duration_seconds=SANDBOX_MONITOR_SECONDS):
    """
    Launches the target file as a subprocess and watches it for a fixed
    duration. Records CPU usage, memory usage, and the number of open files
    and network connections at each check-in. Always terminates the process
    itself once the duration ends, regardless of what happened.
    """
    observations = []
 
    process = subprocess.Popen([file_path])
    watched_process = psutil.Process(process.pid)
 
    start_time = time.time()
    try:
        while time.time() - start_time < duration_seconds:
            if not watched_process.is_running():
                break
 
            snapshot = {
                "timestamp": round(time.time() - start_time, 2),
                "cpu_percent": watched_process.cpu_percent(interval=1),
                "memory_mb": round(watched_process.memory_info().rss / (1024 * 1024), 2),
                "open_files": len(watched_process.open_files()),
                "connections": len(watched_process.connections()),
            }
            observations.append(snapshot)
            logger.info(f"snapshot: {snapshot}")
    finally:
        if watched_process.is_running():
            watched_process.terminate()
 
    return observations
 
def flag_dangerous_behavior(observations, file_threshold=20, connection_threshold=5):
    """
    Reviews the recorded observations for warning signs, such as a sample
    opening an unusually large number of files, which can indicate mass file
    encryption, or opening many network connections, which can indicate
    beaconing to a remote server.
    """
    max_open_files = max((o["open_files"] for o in observations), default=0)
    max_connections = max((o["connections"] for o in observations), default=0)
 
    dangerous = max_open_files >= file_threshold or max_connections >= connection_threshold
    logger.info(f"max_open_files={max_open_files}, max_connections={max_connections}, "
                f"dangerous={dangerous}")
    return dangerous, max_open_files, max_connections