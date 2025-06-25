import os
import json
from datetime import datetime

# === Paths ===
CONTEXT_FILE = "data/context/context.json"
BRUTE_DIR = "data/results"
SMB_DIR = "data/enum"
WEB_DIR = "data/web_attack_results"
MITM_DIR = "data/mitm_captures"
OUT_DIR = "data/enriched"
OUT_FILE = f"{OUT_DIR}/enriched_context.json"

os.makedirs(OUT_DIR, exist_ok=True)

def get_latest_json(directory):
    try:
        files = [f for f in os.listdir(directory) if f.endswith(".json")]
        latest = max(files, key=lambda f: os.path.getmtime(os.path.join(directory, f)))
        with open(os.path.join(directory, latest)) as f:
            return json.load(f)
    except:
        return {}

def enrich_context():
    context = json.load(open(CONTEXT_FILE))
    brute_data = get_latest_json(BRUTE_DIR)
    smb_data = get_latest_json(SMB_DIR)
    web_data = get_latest_json(WEB_DIR)
    mitm_data = get_latest_json(MITM_DIR)

    # === Brute-force Map ===
    brute_map = {x["ip"]: [] for x in brute_data.get("successful_logins", [])}
    for x in brute_data.get("successful_logins", []):
        brute_map[x["ip"]].append(x)

    # === SMB Map ===
    smb_map = {x["ip"]: x.get("shares", []) for x in smb_data.get("results", [])}

    # === Web Map (Aggregate by IP) ===
    web_map = {}
    for entry in web_data.get("results", []):
        ip = entry["target"].split("://")[1].split(":")[0]
        if ip not in web_map:
            web_map[ip] = {
                "form_metadata": [],
                "admin_panels": [],
                "sqli": [],
                "xss": [],
                "lfi": []
            }
        for key in ["form_metadata", "admin_panels", "sqli", "xss", "lfi"]:
            web_map[ip][key].extend(entry.get(key, []))

    # === MITM Ayrıştırması ===
    mitm_logins = [x for x in mitm_data if x.get("type") == "login_attempt"]
    mitm_broadcasts = [x for x in mitm_data if x.get("type") == "broadcast"]
    mitm_http = [x for x in mitm_data if x.get("type") == "http_browsing"]

    for ip, device in context["devices"].items():
        mac = device.get("mac")

        # === Brute-force ===
        logins = brute_map.get(ip, [])
        device["has_login_success"] = int(bool(logins))
        device["login_service_count"] = len(set([x["service"] for x in logins]))
        device["login_credentials"] = [{"service": x["service"], "username": x["username"]} for x in logins]

        # === SMB ===
        shares = smb_map.get(ip, [])
        device["smb_share_count"] = len(shares)
        device["smb_share_names"] = shares

        # === Web attack ===
        web_entry = web_map.get(ip, {})
        device["form_count"] = len(web_entry.get("form_metadata", []))
        device["admin_panel_count"] = len(web_entry.get("admin_panels", []))
        device["web_vuln_count"] = sum(len(web_entry.get(k, [])) for k in ["sqli", "xss", "lfi"])
        device["web_vuln_types"] = [k for k in ["sqli", "xss", "lfi"] if len(web_entry.get(k, [])) > 0]
        device["has_web_vuln"] = int(device["web_vuln_count"] > 0)

        # === MITM ===
        mitm_captures = [x for x in mitm_logins if x.get("src") == mac]
        device["has_mitm_login"] = int(bool(mitm_captures))
        device["captured_data_volume"] = sum(len(x.get("data", "")) for x in mitm_captures)
        device["http_request_count"] = len([x for x in mitm_http if x.get("src") == mac])
        device["broadcast_count"] = len([x for x in mitm_broadcasts if x.get("src") == mac])

        print(f"[DEBUG] Cihaz: {ip}")
        print(f" - Brute logins: {len(logins)}")
        print(f" - SMB shares: {len(shares)}")
        print(f" - Web vulns: {device['web_vuln_types']}")
        print(f" - MITM login: {device['has_mitm_login']}")
        print()

    with open(OUT_FILE, "w") as f:
        json.dump(context, f, indent=4)
    print(f"[✓] Enriched context saved to {OUT_FILE}")

if __name__ == "__main__":
    enrich_context()
