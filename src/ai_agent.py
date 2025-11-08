# src/ai_agent.py
import os
from src.utils_cache import cache_get, cache_set
from dotenv import load_dotenv
load_dotenv()

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
if OPENAI_API_KEY:
    try:
        from openai import OpenAI
        client = OpenAI(api_key=OPENAI_API_KEY)
    except Exception:
        client = None
else:
    client = None

def build_prompt(url, ml_prob, features, enrich=None):
    prompt = f"URL: {url}\nML Prob: {ml_prob:.3f}\nFeatures: {features}\n"
    if enrich:
        prompt += f"Enrichment: {enrich}\n"
    prompt += ("You are a cybersecurity analyst. Decide one of: "
               '"Phishing ⚠️", "Likely Phishing ⚠️", "Safe ✅", "Uncertain 🤔".\n'
               "Give a one-line reason.")
    return prompt

def ai_review(url, ml_prob, features, enrich=None):
    key = f"ai:{url}"
    cached = cache_get("ai", key)
    if cached is not None:
        return cached
    if client is None:
        return "AI unavailable"
    prompt = build_prompt(url, ml_prob, features, enrich)
    resp = client.chat.completions.create(
        model="gpt-4o-mini",  # replace with desired model name, keep within your account
        messages=[
            {"role":"system", "content":"You are a cybersecurity analyst."},
            {"role":"user", "content":prompt}
        ],
        max_tokens=150
    )
    out = resp.choices[0].message.content
    cache_set("ai", key, out, ttl=7*24*3600)
    return out
