import pandas as pd
import joblib
import os
import json
import matplotlib.pyplot as plt
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, precision_recall_fscore_support

DATA_FILE = "data/processed/ai_model_input.csv"
MODEL_FILE = "models/risk_classifier.pkl"
SCALER_FILE = "models/scaler.pkl"
FEATURE_FILE = "models/feature_names.json"
os.makedirs("models", exist_ok=True)

def assign_dynamic_labels(df):
    scores = df.sum(axis=1)
    high_thresh = scores.quantile(0.75)
    low_thresh = scores.quantile(0.25)

    def label(score):
        if score >= high_thresh:
            return "high"
        elif score >= low_thresh:
            return "medium"
        else:
            return "low"

    return scores, scores.apply(label)

print("[~] Loading AI input data...", flush=True)
df = pd.read_csv(DATA_FILE)

if df.empty:
    print("[!] No data found in CSV. Exiting.", flush=True)
    exit()

print("[~] Assigning dynamic risk levels...", flush=True)
X = df.drop(columns=["ip"], errors="ignore")
scores, y = assign_dynamic_labels(X)
X["risk_score"] = scores

print("[~] Scaling features...", flush=True)
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X.drop(columns=["risk_score"], errors="ignore"))

model = RandomForestClassifier(n_estimators=100, random_state=42)
labels = ["low", "medium", "high"]

if len(df) >= 3:
    print("[~] Splitting data into training and test sets...", flush=True)
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.25, random_state=42)
    print("[~] Training model...", flush=True)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    print("[✓] Pre-AI model trained on split data.", flush=True)
    print("[~] Classification report:", flush=True)
    print(classification_report(y_test, y_pred, zero_division=0), flush=True)
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, labels=labels, zero_division=0)
else:
    print(f"[~] Small dataset detected ({len(df)} sample(s)). Training on full data...", flush=True)
    model.fit(X_scaled, y)
    y_pred = model.predict(X_scaled)
    print("[✓] Pre-AI model trained on full data.", flush=True)
    print("[~] Classification report:", flush=True)
    print(classification_report(y, y_pred, zero_division=0), flush=True)
    precision, recall, f1, _ = precision_recall_fscore_support(y, y_pred, labels=labels, zero_division=0)

joblib.dump(model, MODEL_FILE)
joblib.dump(scaler, SCALER_FILE)

with open(FEATURE_FILE, "w") as f:
    json.dump(list(X.drop(columns=["risk_score"]).columns), f)

print(f"[✓] Model saved to: {MODEL_FILE}", flush=True)
print(f"[✓] Scaler saved to: {SCALER_FILE}", flush=True)
print(f"[✓] Feature list saved to: {FEATURE_FILE}", flush=True)

# === TAM TEŞEKKÜLLÜ GRAFİK ===
metrics = [precision, recall, f1]
metric_names = ["Precision", "Recall", "F1-Score"]
colors = ['#4e79a7', '#f28e2b', '#59a14f']
x = np.arange(len(labels))
width = 0.25

plt.figure(figsize=(10, 6))
metrics = [precision, recall, f1]
metric_names = ["Precision", "Recall", "F1-Score"]
colors = ['#4e79a7', '#f28e2b', '#59a14f']
x = np.arange(len(labels))
width = 0.25

for i, (metric, name, color) in enumerate(zip(metrics, metric_names, colors)):
    bars = plt.bar(x + (i - 1) * width, metric, width, label=name, color=color)
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, height + 0.02, f"{height:.2f}",
                 ha='center', va='bottom', fontsize=10)

plt.title("Model Performance per Risk Class (Pre-AI)", fontsize=14, fontweight='bold')
plt.xlabel("Risk Class", fontsize=12)
plt.ylabel("Score", fontsize=12)
plt.xticks(x, labels)
plt.ylim(0, 1.15)
plt.legend(title="Metric", fontsize=10)
plt.grid(axis='y', linestyle='--', alpha=0.6)
plt.figtext(0.99, 0.01, f"Dataset: {DATA_FILE.split('/')[-1]} – {len(df)} samples",
            ha='right', fontsize=9, color='gray')
plt.tight_layout()
plt.show()

