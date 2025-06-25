import pandas as pd
import joblib
import json
import os
from datetime import datetime

MODEL_FILE = "models/risk_classifier_post.pkl"
SCALER_FILE = "models/scaler_post.pkl"
FEATURE_FILE = "models/feature_names_post.json"
DATA_FILE = "data/processed/ai_model_input_post.csv"
SUMMARY_FILE = "data/processed/feature_summary_post.json"
OUTPUT_DIR = "data/target_ranking_post"
os.makedirs(OUTPUT_DIR, exist_ok=True)
OUTPUT_FILE = f"{OUTPUT_DIR}/target_ranking_post_{datetime.now().strftime('%Y_%m_%d_%H_%M')}.json"

required_files = [MODEL_FILE, SCALER_FILE, FEATURE_FILE, DATA_FILE, SUMMARY_FILE]
for path in required_files:
    if not os.path.exists(path):
        print(f"[!] Required file not found: {path}", flush=True)
        exit(1)

print("[~] Loading model, scaler, and feature definitions...", flush=True)
model = joblib.load(MODEL_FILE)
scaler = joblib.load(SCALER_FILE)
with open(FEATURE_FILE) as f:
    expected_features = json.load(f)

print("[~] Reading input and summary files...", flush=True)
df = pd.read_csv(DATA_FILE)
summary = json.load(open(SUMMARY_FILE))

print("[~] Preparing input features...", flush=True)
ips = df["ip"]
X = df.drop(columns=["ip", "risk_score"], errors="ignore")
X = X.reindex(columns=expected_features, fill_value=0)
X_scaled = scaler.transform(X)

print("[~] Predicting risk probabilities...", flush=True)
probas = model.predict_proba(X_scaled)
high_index = list(model.classes_).index("high")

results = []
for i, ip in enumerate(ips):
    risk_score = float(probas[i][high_index])
    label = model.predict([X_scaled[i]])[0]
    explanation = summary.get(str(ip), {}).get("explanation", [])
    results.append({
        "ip": ip,
        "risk_score": round(risk_score, 3),
        "label": label,
        "explanation": explanation
    })

results.sort(key=lambda x: x["risk_score"], reverse=True)

with open(OUTPUT_FILE, "w") as f:
    json.dump(results, f, indent=4)

print(f"[✓] Post-attack target ranking saved → {OUTPUT_FILE}", flush=True)
print("\n[RISKY HOSTS (AFTER ATTACK)]", flush=True)
for entry in results:
    print(f"- {entry['ip']} → {entry['label'].upper()} | Score: {entry['risk_score']} | {len(entry['explanation'])} notes", flush=True)


