import os
import json
import subprocess
from datetime import datetime

CONTEXT_FILE = "data/context/context.json"
STRATEGY_DIR = "data/strategy"
OUTPUT_DIR = "data/enum/"
LOG_FILE = "logs/smb_enum.log"
CREDS_FILE = "logs/found.txt"

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs("logs", exist_ok=True)

def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as log:
        log.write(f"[{timestamp}] {message}\n")

def get_latest_strategy_file():
    try:
        files = [f for f in os.listdir(STRATEGY_DIR) if f.startswith("strategy_map_") and f.endswith(".json")]
        if not files:
            return None
        latest = max(files, key=lambda f: os.path.getmtime(os.path.join(STRATEGY_DIR, f)))
        return os.path.join(STRATEGY_DIR, latest)
    except:
        return None

def load_credentials():
    if not os.path.exists(CREDS_FILE):
        return None, None
    with open(CREDS_FILE) as f:
        for line in f:
            if "(SMB)" in line:
                parts = line.strip().split("→")[-1].strip().split(":")
                if len(parts) == 2:
                    return parts[0], parts[1]
    return None, None

def load_targets():
    strategy_path = get_latest_strategy_file()
    if not os.path.exists(CONTEXT_FILE) or not strategy_path:
        log_event("[ERROR] Context or strategy file not found.")
        return []

    with open(CONTEXT_FILE, "r") as f:
        context = json.load(f)
    with open(strategy_path, "r") as f:
        strategy = json.load(f)

    smb_ips = [ip for ip, mods in strategy.items() if "smb_enum" in mods]
    targets = []

    for ip in smb_ips:
        if ip.startswith("10.50."):
            continue
        info = context["devices"].get(ip)
        if not info:
            continue
        tcp_ports = info.get("protocols", {}).get("tcp", [])
        for port in tcp_ports:
            if port.get("port") == 445 and port.get("state") in ["open", "filtered", "open|filtered"]:
                log_event(f"[MATCH] AI-recommended SMB target → {ip}")
                print(f"[~] [AI-MATCH] {ip} → SMB ENUM target", flush=True)
                targets.append(ip)

    print(f"[~] [DEBUG] Final AI-selected SMB targets: {targets}", flush=True)
    return list(set(targets))

def enumerate_smb_shares(ip, username, password):
    print(f"[~] Enumerating SMB shares on {ip} with {username}:{password}...", flush=True)
    try:
        cmd = [
            "smbclient", "-L", f"//{ip}/", "-U", username,
            "--option=client min protocol=SMB2",
            "--option=client max protocol=SMB3"
        ]
        proc = subprocess.run(cmd, input=f"{password}\n", capture_output=True, text=True, timeout=10)
        output = proc.stdout + proc.stderr

        shares = []
        parsing = False
        for line in output.splitlines():
            if "Sharename" in line:
                parsing = True
                continue
            if parsing:
                if line.strip() == "" or line.strip().startswith("----") or "Server" in line or "Workgroup" in line:
                    continue
                parts = line.split()
                if len(parts) >= 2 and "disabled" not in line.lower() and "no workgroup" not in line.lower():
                    shares.append(parts[0])

        print(f"[✓] {ip} - {len(shares)} share(s) found", flush=True)
        return {
            "ip": ip,
            "shares": shares,
            "username": username,
            "raw_output": output
        }

    except subprocess.TimeoutExpired:
        print(f"[!] {ip} - Timeout during SMB enumeration", flush=True)
        return {
            "ip": ip,
            "shares": [],
            "username": username,
            "raw_output": "Timeout during SMB enumeration"
        }
    except Exception as e:
        print(f"[!] {ip} - Error: {e}", flush=True)
        return {
            "ip": ip,
            "shares": [],
            "username": username,
            "raw_output": f"Error: {e}"
        }

def main():
    username, password = load_credentials()
    if not username or not password:
        print("[!] No SMB credentials found in logs/found.txt.", flush=True)
        log_event("[ERROR] SMB credentials missing. Aborting enumeration.")
        return

    targets = load_targets()
    if not targets:
        print("[!] No SMB targets found.", flush=True)
        return

    results = []
    for ip in targets:
        result = enumerate_smb_shares(ip, username, password)
        results.append(result)

    timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M")
    out_path = os.path.join(OUTPUT_DIR, f"smb_enum_{timestamp}.json")

    with open(out_path, "w") as f:
        json.dump({
            "enum_time": datetime.now().isoformat(),
            "target_count": len(results),
            "results": results
        }, f, indent=4)

    print(f"[✓] Enumeration results saved to: {out_path}", flush=True)

if __name__ == "__main__":
    main()
