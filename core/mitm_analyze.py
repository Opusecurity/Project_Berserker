import os
import re
import json
from datetime import datetime

LOG_FILE = "logs/bettercap_raw.log"
ALIAS_MAP_FILE = "data/context/alias_map.json"
OUTPUT_DIR = "data/mitm_captures"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_alias_map():
    if os.path.exists(ALIAS_MAP_FILE):
        with open(ALIAS_MAP_FILE) as f:
            return json.load(f)
    return {}

def resolve_ip(alias, alias_map):
    cleaned = alias.rstrip(".")
    return alias_map.get(cleaned, alias)

def add_unique(data_dict, ip, key, new_item, alias=None):
    ip_data = data_dict.setdefault(ip, {})
    if alias and "alias" not in ip_data:
        ip_data["alias"] = alias
    values = ip_data.setdefault(key, [])

    if key == "http_request":
        if any(v["method"] == new_item["method"] and v["path"] == new_item["path"] and v["raw"] == new_item["raw"] for v in values):
            return
    elif key == "http_post_data":
        if any(v["data"] == new_item["data"] for v in values):
            return

    values.append(new_item)

def analyze_http_only(log_path, alias_map):
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    results = {}

    i = 0
    while i < len(lines):
        line = ansi_escape.sub("", lines[i]).strip()

        if "[net.sniff.http.request]" in line:
            timestamp = datetime.now().isoformat()
            match_http = re.search(r"http\s+([^\s]+)\s+(GET|POST)\s+([^\s]+)", line)
            if match_http:
                alias = match_http.group(1)
                ip = resolve_ip(alias, alias_map)
                method = match_http.group(2)
                path = match_http.group(3)
                add_unique(results, ip, "http_request", {
                    "timestamp": timestamp,
                    "method": method,
                    "path": path,
                    "raw": line
                }, alias=alias.rstrip("."))

                if method == "POST":
                    body = ""
                    for j in range(1, 20):
                        if i + j < len(lines):
                            next_line = ansi_escape.sub("", lines[i + j]).strip()
                            if re.match(r"^\w+=.*", next_line) or "&" in next_line:
                                body = next_line
                                break
                    if body:
                        add_unique(results, ip, "http_post_data", {
                            "timestamp": timestamp,
                            "data": body
                        }, alias=alias.rstrip("."))
        i += 1

    return results

def save_results(data):
    timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M")
    out_path = os.path.join(OUTPUT_DIR, f"mitm_http_{timestamp}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"[✓] HTTP data saved → {out_path}", flush=True)
    total_entries = sum(len(v) for ip_data in data.values() for k, v in ip_data.items() if isinstance(v, list))
    print(f"[~] Captured {total_entries} unique HTTP entries across {len(data)} IPs.", flush=True)

def main():
    if not os.path.exists(LOG_FILE):
        print("[!] Log file not found.", flush=True)
        return

    alias_map = load_alias_map()
    data = analyze_http_only(LOG_FILE, alias_map)
    if data:
        save_results(data)
    else:
        print("[~] No relevant HTTP data captured.", flush=True)

if __name__ == "__main__":
    main()
