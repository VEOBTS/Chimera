import os
 
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
 
# Polymorphic detection settings
ENTROPY_THRESHOLD = 7.2          # out of a max of 8.0, flags likely packed/encrypted content
ISOLATION_FOREST_CONTAMINATION = 0.05   # expected fraction of anomalies, 5 percent as a starting point
 
# Metamorphic detection settings
HMM_HIDDEN_STATES = 4            # number of hidden behavior states the model tracks
CFG_BRANCH_DENSITY_THRESHOLD = 0.6      # flags unusually dense/tangled control flow
 
# Sandbox isolation settings
SANDBOX_MONITOR_SECONDS = 30     # how long to observe a sample's behavior before deciding