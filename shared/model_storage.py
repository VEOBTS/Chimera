import pickle
import os
 
MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
os.makedirs(MODELS_DIR, exist_ok=True)
 
def save_model(model, name):
    path = os.path.join(MODELS_DIR, f"{name}.pkl")
    with open(path, "wb") as f:
        pickle.dump(model, f)
    return path
 
def load_model(name):
    path = os.path.join(MODELS_DIR, f"{name}.pkl")
    with open(path, "rb") as f:
        return pickle.load(f)