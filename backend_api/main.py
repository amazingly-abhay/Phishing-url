import os
import sys
from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

# Ensure `src` is importable
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.predict import detect_url  # noqa: E402


app = FastAPI(title="Phishing URL Detector API", version="1.0.0")

# Enable CORS for local dev and common origins; adjust in production as needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class DetectRequest(BaseModel):
    url: str
    # Flags are present for future control; current pipeline enriches and AI-reviews by default
    enrich: Optional[bool] = True
    use_ai: Optional[bool] = True


def compute_final_verdict(res_dict: dict) -> str:
    model_pred = (res_dict or {}).get('model_prediction') or ""
    enrichment = (res_dict or {}).get('enrichment') or {}
    ai_text = (res_dict or {}).get('ai_review') or ""
    mp = str(model_pred).strip().lower()
    ai_raw = str(ai_text).strip()
    ai = ai_raw.lower()

    ai_label = None
    if ai.startswith('safe'):
        ai_label = 'safe'
    elif ai.startswith('likely phishing'):
        ai_label = 'likely phishing'
    elif ai.startswith('phishing'):
        ai_label = 'phishing'

    registered_on = None
    ssl_days = None
    if isinstance(enrichment, dict):
        registered_on = enrichment.get('domain_registered_on')
        ssl_days = enrichment.get('ssl_days')

    if ai_label == 'safe':
        return 'Safe'
    if ai_label == 'likely phishing':
        if registered_on or (ssl_days is not None):
            return 'Safe'
        return 'Likely Phishing'
    if ai_label == 'phishing':
        return 'Phishing'

    if mp == 'phishing':
        return 'Phishing'
    return 'Safe'


@app.post("/api/detect")
def detect(req: DetectRequest):
    url = (req.url or "").strip()
    if not url:
        return {"error": "url required"}

    result = detect_url(url)
    if isinstance(result, dict):
        final = compute_final_verdict(result)
        return {**result, "final_verdict": final}
    return {"raw": result}


@app.get("/api/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))


