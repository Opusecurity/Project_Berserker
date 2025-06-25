import os
import json
import joblib
import pandas as pd
from datetime import datetime

CSV_FILE = "data/processed/ai_model_input.csv"
CONTEXT_FILE = "data/context/context.json"
MODEL_FILE = "models/risk_classifier.pkl"
SCALER_FILE = "models/scaler.pkl"
FEATURE_FILE = "models/feature_names.json"
OUTPUT_DIR = "data/strategy"
os.makedirs(OUTPUT_DIR, exist_ok=True)
OUT_FILE = f"{OUTPUT_DIR}/strategy_map_{datetime.now().strftime('%Y_%m_%d_%H_%M')}.json"

def get_module_suggestions(ip, context_entry):
    tcp_ports = [
        p["port"] for p in context_entry.get("protocols", {}).get("tcp", [])
        if p.get("state") == "open"
    ]
    modules = []

    if 22 in tcp_ports or 21 in tcp_ports:
        modules.append("brute_force")
    if 80 in tcp_ports or 443 in tcp_ports:
        modules.append("web_attack")
    if 445 in tcp_ports:
        modules.append("smb_enum")

    is_gateway = context_entry.get("is_gateway", 0)
    if is_gateway == 0 and 80 in tcp_ports:
        modules.append("mitm_attack")

    return modules

def load_context():
    try:
        with open(CONTEXT_FILE) as f:
            return json.load(f).get("devices", {})
    except Exception as e:
        print(f"[!] Failed to load context.json: {e}", flush=True)
        return {}

def load_ai_input():
    try:
        return pd.read_csv(CSV_FILE)
    except Exception as e:
        print(f"[!] Failed to load AI input CSV: {e}", flush=True)
        return None

def load_model_and_scaler():
    try:
        model = joblib.load(MODEL_FILE)
        scaler = joblib.load(SCALER_FILE)
        return model, scaler
    except Exception as e:
        print(f"[!] Failed to load model or scaler: {e}", flush=True)
        return None, None

def align_features(df):
    try:
        with open(FEATURE_FILE) as f:
            expected_features = json.load(f)
        X = df.drop(columns=["ip"], errors="ignore")
        X = X.reindex(columns=expected_features, fill_value=0)
        return X
    except Exception as e:
        print(f"[!] Feature alignment error: {e}", flush=True)
        return None

def generate_strategy_map(df, predictions, context):
    strategy_map = {}

    for i, row in df.iterrows():
        ip = row["ip"]
        risk_level = predictions[i]
        context_entry = context.get(ip, {})
        suggested = get_module_suggestions(ip, context_entry)

        if risk_level == "low":
            if ip.endswith(".1") and "mitm_attack" in suggested:
                strategy_map[ip] = ["mitm_attack"]
            else:
                strategy_map[ip] = []
        else:
            strategy_map[ip] = suggested

    return strategy_map

def save_strategy_map(strategy_map):
    with open(OUT_FILE, "w") as f:
        json.dump(strategy_map, f, indent=4)
    print(f"[✓] Strategy map saved to: {OUT_FILE}", flush=True)

def main():
    print("[~] Generating AI-based port-oriented attack strategy suggestions...", flush=True)

    df = load_ai_input()
    if df is None:
        return

    model, scaler = load_model_and_scaler()
    if model is None or scaler is None:
        return

    X = align_features(df)
    if X is None:
        return

    context = load_context()
    X_scaled = scaler.transform(X)
    predictions = model.predict(X_scaled)

    print("\n[✓] AI Predictions:", flush=True)
    for ip, label in zip(df["ip"], predictions):
        print(f" - {ip}: {label}", flush=True)

    strategy_map = generate_strategy_map(df, predictions, context)
    save_strategy_map(strategy_map)

if __name__ == "__main__":
    main()
