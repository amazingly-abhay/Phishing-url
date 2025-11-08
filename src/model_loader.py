# src/model_loader.py
import os
import joblib

MODEL_PATH = os.path.join(os.path.dirname(__file__), "../model/phishing_model.pkl")
_model = None

def load_model():
    """Load and cache the trained model."""
    global _model
    if _model is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"Model not found at {MODEL_PATH}")
        _model = joblib.load(MODEL_PATH)
    return _model
