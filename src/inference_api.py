# src/inference_api.py
import os, joblib, numpy as np
from fastapi import FastAPI
from pydantic import BaseModel
from features import extract_lexical, encode_url_chars
from utils_cache import cache_get, cache_set
from ai_agent import ai_review
from enrich_async import run_enrich_sync
import uvicorn
from dotenv import load_dotenv
load_dotenv()

MODEL_PATH = "../model/phishing_model.pkl"
app = FastAPI(title="PhishCheck")

# Load model
if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
else:
    model = None
    print("⚠️ Warning: No trained model found at", MODEL_PATH)

# thresholds
LOW_THRESH = float(os.environ.get("LOW_THRESH", 0.10))
HIGH_THRESH = float(os.environ.get("HIGH_THRESH", 0.85))

class CheckRequest(BaseModel):
    url: str
    use_ai: bool = False
    enrich: bool = False

@app.post("/check")
def check(req: CheckRequest):
    url = req.url.strip()
    if not url:
        return {"error":"url required"}
    feats = extract_lexical(url)
    if model is None:
        # fallback heuristic
        score = min(0.5, feats[11] / (len(feats) or 1)) if isinstance(feats, list) else 0.5
        return {"url":url, "ml_prob":score, "final":"Uncertain"}
    prob = model.predict_proba([feats])[0][1]  # probability of phishing
    result = {"url":url, "ml_prob":float(prob)}
    # decide
    if prob >= HIGH_THRESH:
        result["final"] = "Phishing ⚠️"
        result["action"] = "block"
    elif prob <= LOW_THRESH:
        result["final"] = "Safe ✅"
    else:
        # borderline
        result["final"] = "Borderline"
        if req.enrich:
            enrich = run_enrich_sync([url], concurrency=6)
            domain = list(enrich.keys())[0]
            enrich_info = enrich[domain]
            result["enrich"] = enrich_info
        else:
            enrich_info = None

        if req.use_ai:
            ai = ai_review(url, prob, feats, enrich_info)
            result["ai"] = ai
            if "Phishing" in ai:
                result["final"] = "Phishing ⚠️"
            elif "Safe" in ai:
                result["final"] = "Safe ✅"
            else:
                result["final"] = "Uncertain 🤔"

    return result

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
