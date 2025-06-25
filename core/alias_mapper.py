import os
import re
import json

LOG_FILE = "logs/bettercap_raw.log"
STRATEGY_DIR = "data/strategy"
OUTPUT_FILE = "data/context/alias_map.json"

os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

def get_latest_strategy_file():
    files = [f for f in os.listdir(STRATEGY_DIR) if f.startswith("strategy_map_") and f.endswith(".json")]
    if not files:
        return None
    latest_file = sorted(files)[-1]
    return os.path.join(STRATEGY_DIR, latest_file)

def load_target_ips():
    strategy_file = get_latest_strategy_file()
    if not strategy_file or not os.path.exists(strategy_file):
        print(f"[!] No strategy_map file found in {STRATEGY_DIR}", flush=True)
        return []
    with open(strategy_file) as f:
        strategy_map = json.load(f)
    return [ip for ip in strategy_map if re.match(r"\d{1,3}(\.\d{1,3}){3}", ip)]

def extract_alias_map(log_path, target_ips):
    alias_map = {}
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = ansi_escape.sub("", line).strip()

            match_mdns = re.search(r"\[net\.sniff\.mdns\].*?mdns\s+(?P<alias>[^\s:]+)\s+.*?is\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})", line)
            if match_mdns:
                alias = match_mdns.group("alias").strip().rstrip(".")
                ip = match_mdns.group("ip").strip()
                if not re.match(r"\d{1,3}(?:\.\d{1,3}){3}", alias):  # IP'yi alias olarak alma
                    alias_map[alias] = ip
                continue

            match_http = re.search(r"http\s+(?P<alias>[^\s]+)\s+(GET|POST)", line)
            if match_http:
                alias = match_http.group("alias").strip()
                if alias not in alias_map and not re.match(r"\d{1,3}(?:\.\d{1,3}){3}", alias):
                    if len(target_ips) == 1:
                        alias_map[alias] = target_ips[0]
                    else:
                        alias_map[alias] = "UNKNOWN"
                continue

    return alias_map

def save_alias_map(alias_map):
    with open(OUTPUT_FILE, "w") as f:
        json.dump(alias_map, f, indent=4)
    print(f"[✓] Alias map saved to {OUTPUT_FILE}", flush=True)
    print(f"[~] Total aliases: {len(alias_map)}", flush=True)

def main():
    if not os.path.exists(LOG_FILE):
        print(f"[!] Log file not found: {LOG_FILE}", flush=True)
        return

    print("[~] Loading target IPs from latest strategy_map...", flush=True)
    target_ips = load_target_ips()
    if not target_ips:
        print("[!] No target IPs found. Please update your strategy_map.", flush=True)
        return

    print(f"[~] Found {len(target_ips)} target IP(s). Extracting alias map...", flush=True)
    alias_map = extract_alias_map(LOG_FILE, target_ips)
    if alias_map:
        save_alias_map(alias_map)
    else:
        print("[!] No alias data found in log.", flush=True)

if __name__ == "__main__":
    main()
