import subprocess
import re
import tempfile
import os

def trace_syscalls(binary_path, timeout_seconds=2):
    """
    Runs a binary under strace for a short, bounded time, and returns
    the ordered list of syscall names it made. Input and output are
    both discarded, and the run is capped so nothing hangs waiting
    on user input.
    """
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        trace_file = tmp.name

    try:
        try:
            subprocess.run(
                ["strace", "-f", "-o", trace_file, "timeout", str(timeout_seconds), binary_path],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout_seconds + 3,
            )
        except subprocess.TimeoutExpired:
            pass

        calls = []
        with open(trace_file) as f:
            for line in f:
                match = re.match(r'^(?:\d+\s+)?(\w+)\(', line)
                if match:
                    calls.append(match.group(1))
        return calls
    finally:
        if os.path.exists(trace_file):
            os.remove(trace_file)