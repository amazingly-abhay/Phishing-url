# import os
# import pandas as pd
# import joblib
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.model_selection import train_test_split
# from sklearn.metrics import classification_report
# from features import extract_features

# # File paths
# csv_path = "../data/phishing_data.csv"
# model_path = "../model/phishing_model.pkl"

# # Ensure model directory exists
# os.makedirs("../model", exist_ok=True)

# # Load CSV with only 2 columns
# try:
#     df = pd.read_csv(
#         csv_path,
#         usecols=[0, 1],
#         names=["URL", "Label"],
#         header=0,
#         on_bad_lines="skip",
#         dtype=str,
#         low_memory=False
#     )
# except Exception as e:
#     print(f"❌ Error reading CSV: {e}")
#     exit()

# # Clean and filter data
# df = df[df["URL"].notnull() & df["Label"].notnull()]
# df["Label"] = df["Label"].map({"bad": 1, "good": 0}).fillna(df["Label"])

# # Only keep numeric 0 and 1 labels
# df = df[df["Label"].astype(str).isin(["0", "1"])]
# df["Label"] = df["Label"].astype(int)

# print(f"📦 Loaded {len(df)} clean samples.")

# # Check if there's any data left
# if df.empty:
#     print("❌ No valid data found to train the model.")
#     exit()

# # Extract features
# print("🧠 Extracting features...")
# X = df["URL"].apply(lambda url: extract_features(url))
# X = pd.DataFrame(X.tolist())
# y = df["Label"]

# # Final validation
# if X.empty or y.empty:
#     print("❌ Feature extraction failed or labels missing.")
#     exit()

# # Train/test split
# X_train, X_test, y_train, y_test = train_test_split(
#     X, y, test_size=0.2, random_state=42
# )

# # Train model
# print("⚙️ Training model...")
# model = RandomForestClassifier(n_estimators=100, random_state=42)
# model.fit(X_train, y_train)

# # Evaluate
# print("\n📊 Classification Report:\n")
# y_pred = model.predict(X_test)
# print(classification_report(y_test, y_pred))

# # Save model
# joblib.dump(model, model_path)
# print(f"\n✅ Model saved at: {model_path}")


















# import pandas as pd
# import re
# import tldextract
# import numpy as np
# from tqdm import tqdm
# from multiprocessing import Pool, cpu_count
# import joblib
# import os
# from urllib.parse import urlparse
# from sklearn.model_selection import train_test_split
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.metrics import classification_report, accuracy_score

# tqdm.pandas()

# # =====================================================
# # SAFE, FAST FEATURE EXTRACTION (no live web requests)
# # =====================================================
# def extract_features(url):
#     try:
#         features = {}
#         parsed = urlparse(url)
#         domain_info = tldextract.extract(url)
#         domain = domain_info.domain + '.' + domain_info.suffix

#         # ----- Lexical features -----
#         features['url_length'] = len(url)
#         features['hostname_length'] = len(parsed.netloc)
#         features['path_length'] = len(parsed.path)
#         features['count_dot'] = url.count('.')
#         features['count_hyphen'] = url.count('-')
#         features['count_at'] = url.count('@')
#         features['count_question'] = url.count('?')
#         features['count_equal'] = url.count('=')
#         features['count_slash'] = url.count('/')
#         features['count_digit'] = sum(c.isdigit() for c in url)
#         features['count_letter'] = sum(c.isalpha() for c in url)
#         features['use_https'] = 1 if parsed.scheme == 'https' else 0

#         # ----- Domain-related -----
#         features['subdomain_count'] = len(domain_info.subdomain.split('.')) if domain_info.subdomain else 0
#         features['tld_length'] = len(domain_info.suffix)
#         features['domain_length'] = len(domain)
#         features['is_ip'] = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', parsed.netloc) else 0

#         # ----- Special patterns -----
#         features['has_login'] = 1 if re.search(r'login|signin', url.lower()) else 0
#         features['has_secure'] = 1 if 'secure' in url.lower() else 0
#         features['has_bank'] = 1 if 'bank' in url.lower() else 0
#         features['has_verify'] = 1 if 'verify' in url.lower() else 0

#         return features
#     except Exception:
#         # Return default NaN-filled dict if parsing fails
#         return {key: np.nan for key in [
#             'url_length','hostname_length','path_length','count_dot','count_hyphen','count_at',
#             'count_question','count_equal','count_slash','count_digit','count_letter','use_https',
#             'subdomain_count','tld_length','domain_length','is_ip','has_login','has_secure','has_bank','has_verify'
#         ]}

# # =====================================================
# # PARALLEL FEATURE EXTRACTION
# # =====================================================
# def extract_features_parallel(urls, cache_file="cached_features.pkl"):
#     if os.path.exists(cache_file):
#         print(f"🔄 Loading cached features from {cache_file}")
#         return joblib.load(cache_file)

#     print("⚙️ Extracting features in parallel...")
#     with Pool(processes=max(4, cpu_count() - 1)) as pool:
#         results = list(tqdm(pool.imap(extract_features, urls), total=len(urls)))

#     df = pd.DataFrame(results)
#     joblib.dump(df, cache_file)
#     print(f"✅ Cached extracted features in {cache_file}")
#     return df

# # =====================================================
# # MAIN PIPELINE
# # =====================================================
# if __name__ == "__main__":
#     print("📥 Loading dataset...")
#     df = pd.read_csv("../data/phishing_dataset.csv")  # Change path to your dataset
#     print(f"📦 Loaded {len(df)} URLs")

#     # Ensure dataset has 'url' and 'label'
#     if 'url' not in df.columns or 'label' not in df.columns:
#         raise ValueError("Dataset must contain 'url' and 'label' columns")

#     urls = df['url'].tolist()
#     labels = df['label'].values

#     # Feature extraction
#     X = extract_features_parallel(urls)
#     X['label'] = labels

#     # Clean missing values
#     X = X.fillna(0)

#     # Split for training
#     X_train, X_test, y_train, y_test = train_test_split(
#         X.drop(columns=['label']), X['label'], test_size=0.2, random_state=42
#     )

#     # Train a fast baseline model
#     print("🧠 Training Random Forest model...")
#     model = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
#     model.fit(X_train, y_train)

#     preds = model.predict(X_test)
#     acc = accuracy_score(y_test, preds)
#     print(f"\n✅ Accuracy: {acc*100:.2f}%")
#     print(classification_report(y_test, preds))

#     # Save model
#     joblib.dump(model, "../models/phishing_rf_model.pkl")
#     print("💾 Model saved at ../models/phishing_rf_model.pkl")




































# import os
# import time
# import pandas as pd
# import joblib
# from tqdm import tqdm
# from concurrent.futures import ThreadPoolExecutor, as_completed
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.model_selection import train_test_split
# from sklearn.metrics import classification_report
# from features import extract_features  # make sure this imports your enhanced extract_features()

# # -------------------------------
# # CONFIG
# # -------------------------------
# CSV_PATH = "../data/phishing_data.csv"
# MODEL_PATH = "../model/phishing_model.pkl"
# MAX_WORKERS = 100  # number of parallel threads
# os.makedirs("../model", exist_ok=True)

# # -------------------------------
# # LOAD DATA
# # -------------------------------
# print("📂 Loading dataset...")
# try:
#     df = pd.read_csv(
#         CSV_PATH,
#         usecols=[0, 1],
#         names=["URL", "Label"],
#         header=0,
#         on_bad_lines="skip",
#         dtype=str,
#         low_memory=False
#     )
# except Exception as e:
#     print(f"❌ Error reading CSV: {e}")
#     exit()

# # Clean and filter
# df = df[df["URL"].notnull() & df["Label"].notnull()]
# df["Label"] = df["Label"].map({"bad": 1, "good": 0}).fillna(df["Label"])
# df = df[df["Label"].astype(str).isin(["0", "1"])]
# df["Label"] = df["Label"].astype(int)

# print(f"✅ Loaded {len(df):,} clean samples.")

# if df.empty:
#     print("❌ No valid data found to train the model.")
#     exit()

# # -------------------------------
# # FEATURE EXTRACTION (Parallel)
# # -------------------------------
# print(f"🧠 Extracting features for {len(df):,} URLs using {MAX_WORKERS} threads...")
# start_time = time.time()
# urls = df["URL"].tolist()
# features_list = []

# with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
#     futures = {executor.submit(extract_features, url): url for url in urls}
#     for future in tqdm(as_completed(futures), total=len(urls), desc="Extracting"):
#         try:
#             features_list.append(future.result())
#         except Exception:
#             features_list.append([0] * 30)  # fallback for errors

# elapsed = time.time() - start_time
# print(f"✅ Feature extraction completed in {elapsed/60:.2f} minutes.")

# X = pd.DataFrame(features_list)
# y = df["Label"]

# if X.empty or y.empty:
#     print("❌ Feature extraction failed or no labels found.")
#     exit()

# # -------------------------------
# # TRAIN / TEST SPLIT
# # -------------------------------
# print("🔀 Splitting data into train/test sets...")
# X_train, X_test, y_train, y_test = train_test_split(
#     X, y, test_size=0.2, random_state=42
# )

# # -------------------------------
# # TRAIN MODEL
# # -------------------------------
# print("⚙️ Training Random Forest model...")
# model = RandomForestClassifier(
#     n_estimators=200,
#     max_depth=None,
#     random_state=42,
#     n_jobs=-1  # use all cores for training
# )
# model.fit(X_train, y_train)

# # -------------------------------
# # EVALUATE
# # -------------------------------
# print("\n📊 Classification Report:\n")
# y_pred = model.predict(X_test)
# print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))

# # -------------------------------
# # SAVE MODEL
# # -------------------------------
# joblib.dump(model, MODEL_PATH)
# print(f"\n✅ Model saved successfully at: {MODEL_PATH}")
# print("🚀 Training complete!")


























# # src/train_model.py
# import os, time, joblib
# import pandas as pd
# from tqdm import tqdm
# from multiprocessing import Pool, cpu_count
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.model_selection import train_test_split
# from sklearn.metrics import classification_report, accuracy_score
# from features import extract_lexical

# # CONFIG
# CSV_PATH = "../data/phishing_data.csv"   # ensure this exists
# MODEL_PATH = "../model/phishing_model.pkl"
# CACHE_PATH = "../model/feature_cache.pkl"
# os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

# N_PROCESSES = max(1, cpu_count() - 1)

# def _imap_extract(urls):
#     """Used by Pool.imap; keeps one-arg signature."""
#     return list(urls)  # placeholder (we won't call it)

# def extract_parallel(urls):
#     if os.path.exists(CACHE_PATH):
#         print(f"🔁 Loading cached features: {CACHE_PATH}")
#         return joblib.load(CACHE_PATH)

#     print("⚙️ Extracting features in parallel...")
#     with Pool(N_PROCESSES) as pool:
#         results = list(tqdm(pool.imap(extract_lexical, urls, chunksize=200),
#                             total=len(urls), desc="Extracting", ncols=100))
#     df_feats = pd.DataFrame(results)
#     joblib.dump(df_feats, CACHE_PATH)
#     print(f"✅ Cached features to {CACHE_PATH}")
#     return df_feats

# def main():
#     t0 = time.time()
#     print("📥 Loading dataset...")
#     if not os.path.exists(CSV_PATH):
#         raise FileNotFoundError(f"CSV not found: {CSV_PATH}")
#     df = pd.read_csv(CSV_PATH)
#     # Expect columns 'url' and 'label' (0 safe, 1 phishing)
#     if 'url' not in df.columns or 'label' not in df.columns:
#         # attempt common fallback
#         cols = df.columns.tolist()
#         print("⚠️ Dataset columns:", cols)
#         raise ValueError("Dataset must contain 'url' and 'label' columns")
#     print(f"📦 Loaded {len(df):,} rows")

#     urls = df['url'].astype(str).tolist()
#     labels = df['label'].astype(int).values

#     feats_df = extract_parallel(urls)
#     feats_df = feats_df.fillna(0)
#     feats_df['label'] = labels

#     X = feats_df.drop(columns=['label'])
#     y = feats_df['label']

#     X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

#     print("🧠 Training RandomForest...")
#     model = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=42, class_weight='balanced')
#     model.fit(X_train, y_train)

#     y_pred = model.predict(X_test)
#     print("\n📊 Metrics:\n", classification_report(y_test, y_pred))
#     print("Accuracy:", accuracy_score(y_test, y_pred))

#     joblib.dump(model, MODEL_PATH)
#     print(f"💾 Model saved to {MODEL_PATH}")

#     print(f"⏱ Total time: {(time.time() - t0)/60:.2f} minutes")

# if __name__ == "__main__":
#     main()











































# src/train_model.py
import os
import time
import joblib
import pandas as pd
from tqdm import tqdm
from multiprocessing import Pool, cpu_count
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from features import extract_features

CSV_PATH = "../data/phishing_data.csv"  # Update path to your CSV
MODEL_PATH = "../model/phishing_model.pkl"
os.makedirs("../model", exist_ok=True)
N_PROCESSES = max(cpu_count() - 1, 1)

def parallel_extract(urls):
    """Parallel feature extraction"""
    with Pool(N_PROCESSES) as pool:
        results = list(tqdm(pool.imap(extract_features, urls, chunksize=200),
                            total=len(urls),
                            desc="🔍 Extracting features",
                            ncols=100))
    return results

def main():
    start = time.time()
    print("📥 Loading dataset...")
    df = pd.read_csv(CSV_PATH)
    df.columns = ['url','label']  # Make sure CSV has two columns
    df = df.dropna(subset=['url','label'])
    df['label'] = df['label'].map({"bad":1,"good":0}).fillna(df['label']).astype(int)
    print(f"📦 Loaded {len(df)} URLs")

    # Feature extraction
    print("\n🧠 Starting feature extraction...")
    X = parallel_extract(df['url'].tolist())
    X = pd.DataFrame(X)
    y = df['label']
    print(f"✅ Feature extraction done | Shape: {X.shape}")

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train model
    print("\n⚙️ Training Random Forest...")
    model = RandomForestClassifier(n_estimators=300, max_depth=25, n_jobs=-1, random_state=42)
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    print("\n📊 Evaluation Report:\n", classification_report(y_test, y_pred))

    # Save
    joblib.dump(model, MODEL_PATH)
    print(f"\n💾 Model saved at: {MODEL_PATH}")
    print(f"⏱ Total runtime: {(time.time()-start)/60:.2f} min")

if __name__ == "__main__":
    main()
