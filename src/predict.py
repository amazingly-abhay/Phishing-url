# import joblib
# from .features import extract_features

# def detect_url(url):
#     model = joblib.load("../model/phishing_model.pkl")
#     features = extract_features(url)
#     prediction = model.predict([features])[0]
#     return "Safe ✅" if prediction == 0 else "Phishing ⚠️"
















# # src/predict.py
# import joblib
# import os
# from .features import extract_features

# MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../model/phishing_model.pkl"))

# # Load trained model
# model = joblib.load(MODEL_PATH)

# def detect_url(url: str) -> str:
#     """Predicts if URL is phishing or safe."""
#     features = extract_features(url)
#     pred = model.predict([features])[0]
#     return "Phishing" if pred == 1 else "Safe"























# src/predict.py
import asyncio
from src.model_loader import load_model
from src.features import extract_features
from src.enrich_async import enrich_url_async
from src.ai_agent import ai_review

# Load model once
model = load_model()

async def _detect_url_async(url: str) -> dict:
    result = {}

    # 1️⃣ Model prediction
    try:
        features = extract_features(url)
        pred = model.predict([features])[0]
        result['model_prediction'] = "Phishing" if pred == 1 else "Safe"
    except Exception as e:
        result['model_prediction'] = f"Error: {e}"

    # 2️⃣ Domain/SSL/Page enrichment
    try:
        enrichment = await enrich_url_async(url)
        result['enrichment'] = enrichment
    except Exception as e:
        result['enrichment'] = f"Error: {e}"

    # 3️⃣ AI review
    try:
        # compute probability if available
        try:
            proba = model.predict_proba([features])[0]
            ml_prob = float(proba[pred]) if hasattr(proba, "__getitem__") else 0.0
        except Exception:
            ml_prob = 0.0
        ai_result = ai_review(url, ml_prob, features, result.get('enrichment'))
        result['ai_review'] = ai_result
    except Exception as e:
        result['ai_review'] = f"Error: {e}"

    return result

def detect_url(url: str) -> dict:
    """Synchronous wrapper for CLI."""
    return asyncio.run(_detect_url_async(url))
















# import joblib
# from .features import extract_features

# MODEL_PATH = "../model/phishing_model.pkl"

# def detect_url(url):
#     try:
#         model = joblib.load(MODEL_PATH)
#     except Exception as e:
#         return f"❌ Model not found or invalid: {e}"

#     features = extract_features(url)
#     prediction = model.predict([features])[0]
#     probability = model.predict_proba([features])[0][prediction]

#     label = "Safe ✅" if prediction == 0 else "Phishing ⚠️"
#     confidence = f"{probability * 100:.2f}%"
#     return f"{label} (Confidence: {confidence})"




















# import os
# import joblib

# from dotenv import load_dotenv
# load_dotenv()  # Automatically loads .env variables


# try:
#     from openai import OpenAI
#     OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
#     openai_ready = OPENAI_API_KEY is not None and len(OPENAI_API_KEY) > 0
# except ImportError:
#     openai_ready = False
# from .features import extract_features

# if openai_ready:
#     client = OpenAI(api_key=OPENAI_API_KEY)

# def ai_review(url, ml_label, features):
#     if not openai_ready:
#         return "OpenAI integration unavailable. Only ML result used."
#     prompt = f"""
#     URL: {url}
#     ML Prediction: {'Phishing' if ml_label else 'Safe'}
#     Features: {features}

#     As a cybersecurity AI expert, determine if this URL is truly safe or phishing
#     based on:
#     - Domain age
#     - SSL certificate validity
#     - WHOIS data
#     - DNS and email records
#     - Page content (e.g., login forms, suspicious links)
#     - URL lexical pattern and reputation

#     Give a clear final judgment as one of:
#     - "Phishing ⚠️"
#     - "Likely Phishing ⚠️"
#     - "Safe ✅"
#     - "Uncertain 🤔"
#     Include a brief reason (1–2 lines).
#     """
#     response = client.chat.completions.create(
#         model="gpt-5",
#         messages=[
#             {"role": "system", "content": "You are a cybersecurity AI agent that analyzes URLs for phishing risk."},
#             {"role": "user", "content": prompt}
#         ]
#     )
#     return response.choices[0].message.content

# def detect_url(url):
#     """
#     Combines ML-based detection with AI-based validation if OpenAI is available.
#     """
#     model = joblib.load("../model/phishing_model.pkl")
#     features = extract_features(url)

#     ml_prediction = model.predict([features])[0]
#     ml_label = bool(ml_prediction)  # 1 = phishing, 0 = safe

#     # Use GPT-5 for intelligent validation, if available
#     ai_result = ai_review(url, ml_label, features) if openai_ready else None

#     if ai_result and "Phishing" in ai_result:
#         final_decision = "Phishing ⚠️"
#     elif ai_result and "Safe" in ai_result:
#         final_decision = "Safe ✅"
#     else:
#         final_decision = "Phishing ⚠️" if ml_label else "Safe ✅"

#     if ai_result:
#         print("\n--- AI Agent Review ---")
#         print(ai_result)
#         print("-----------------------")

#     return final_decision
