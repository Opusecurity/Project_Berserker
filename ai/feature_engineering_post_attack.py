import json
import csv
import os
from datetime import datetime

PENTEST_RESULTS_FILE = "data/pentest_results/pentest_results.json"
OUT_CSV = "data/processed/ai_model_input_post.csv"
OUT_SUMMARY = "data/processed/feature_summary_post.json"
os.makedirs("data/processed", exist_ok=True)

def extract_post_features():
    with open(PENTEST_RESULTS_FILE, "r") as f:
        data = json.load(f)

    features = {}
    summary = {}
    ips = set()

    # Tüm IP'leri tespit et (her kaynaktan)
    for key in ["brute_force", "smb_enum", "web_attack", "mitm"]:
        section = data.get(key, {})
        if isinstance(section, list):
            for item in section:
                if isinstance(item, dict) and "ip" in item:
                    ips.add(item["ip"])
        elif isinstance(section, dict):
            for val in section.values():
                if isinstance(val, list):
                    for item in val:
                        if isinstance(item, dict) and "ip" in item:
                            ips.add(item["ip"])
            for item in section.get("results", []):
                if isinstance(item, dict):
                    if "ip" in item:
                        ips.add(item["ip"])
                    elif "target" in item:
                        ip = item["target"].split("//")[-1].split(":")[0]
                        ips.add(ip)

    for ip in ips:
        features[ip] = {
            "brute_force_success": 0,
            "brute_force_failed": 0,
            "sqli_count": 0,
            "xss_count": 0,
            "lfi_count": 0,
            "smb_anonymous": 0,
            "mitm_credentials": 0
        }

    # Brute Force
    for item in data.get("brute_force", {}).get("successful_logins", []):
        ip = item.get("ip")
        if ip in features:
            features[ip]["brute_force_success"] += 1

    for item in data.get("brute_force", {}).get("failed_logins", []):
        ip = item.get("ip")
        if ip in features:
            features[ip]["brute_force_failed"] += 1

    # SMB ENUM
    for item in data.get("smb_enum", {}).get("results", []):
        ip = item.get("ip")
        shares = item.get("shares", [])
        if ip in features and shares:
            features[ip]["smb_anonymous"] = 1  # Açık varsa bayrak yakar

    # Web Attack
    for entry in data.get("web_attack", {}).get("results", []):
        ip = entry.get("target", "").split("//")[-1].split(":")[0]
        if ip in features:
            for vuln_type in ["sqli", "xss", "lfi"]:
                features[ip][f"{vuln_type}_count"] += len(entry.get(vuln_type, []))

    # MITM – Tamamen dinamik credential algılaması
    for item in data.get("mitm", []):
        if isinstance(item, dict):
            ip = item.get("ip")
            content = item.get("data", "").strip()

            # Veri HTTP POST datasına benziyorsa (key=value&key2=value2...)
            if ip in features and "=" in content and "&" in content:
                pairs = content.split("&")
                kv_pairs = [p for p in pairs if "=" in p and len(p.split("=")[0]) > 1 and len(p.split("=")[1]) > 0]
                if len(kv_pairs) >= 2:
                    features[ip]["mitm_credentials"] += 1

    # CSV ve özet için çıktı oluştur
    rows = []
    for ip, feats in features.items():
        row = {"ip": ip, **feats}
        rows.append(row)
        explanation = []
        for k, v in feats.items():
            if v:
                explanation.append(f"{k}: {v}")
        summary[ip] = {"features": feats, "explanation": explanation}

    return rows, summary

def save_outputs(rows, summary):
    with open(OUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"[✓] AI input CSV saved → {OUT_CSV}", flush=True)

    with open(OUT_SUMMARY, "w") as f:
        json.dump(summary, f, indent=4)
    print(f"[✓] Feature summary saved → {OUT_SUMMARY}", flush=True)

if __name__ == "__main__":
    rows, summary = extract_post_features()
    save_outputs(rows, summary)
