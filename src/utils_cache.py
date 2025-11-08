# src/utils_cache.py
import os, json, time, hashlib

CACHE_DIR = os.environ.get("PHISH_CACHE_DIR", "/tmp/phish_cache")
os.makedirs(CACHE_DIR, exist_ok=True)

def _key_to_path(prefix: str, key: str):
    h = hashlib.sha1(key.encode()).hexdigest()
    return os.path.join(CACHE_DIR, f"{prefix}_{h}.json")

def cache_set(prefix: str, key: str, value, ttl: int = 7*24*3600):
    path = _key_to_path(prefix, key)
    obj = {"ts": time.time(), "ttl": ttl, "value": value}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f)

def cache_get(prefix: str, key: str):
    path = _key_to_path(prefix, key)
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        if time.time() - obj.get("ts",0) > obj.get("ttl", 0):
            return None
        return obj.get("value")
    except Exception:
        return None
