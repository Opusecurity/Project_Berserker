import json
import os
import ipaddress
from datetime import datetime

SNIFFER_DIR = "data/sniffed/"
SCANNER_DIR = "data/raw/"
ARP_DIR = "data/arp/"
OUTPUT_FILE = "data/context/context.json"
LOG_FILE = "logs/context_builder.log"

os.makedirs("data/context/", exist_ok=True)
os.makedirs("logs", exist_ok=True)

def log_event(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {msg}\n")

def load_latest_json(path):
    files = sorted([f for f in os.listdir(path) if f.endswith(".json")])
    if not files:
        msg = f"[!] No JSON files found in {path}"
        print(msg, flush=True)
        log_event(msg)
        return {}
    latest_file = os.path.join(path, files[-1])
    print(f"[~] Loaded {latest_file}", flush=True)
    log_event(f"Loaded latest file: {latest_file}")
    with open(latest_file) as f:
        return json.load(f)

def load_latest_arp_map():
    try:
        files = sorted([f for f in os.listdir(ARP_DIR) if f.endswith(".json")])
        if not files:
            print("[!] ARP resolver data not found.", flush=True)
            log_event("[!] ARP resolver data not found.")
            return {}
        latest_file = os.path.join(ARP_DIR, files[-1])
        with open(latest_file) as f:
            data = json.load(f)
            print(f"[~] Loaded ARP data → {latest_file}", flush=True)
            log_event(f"Loaded ARP resolver data: {latest_file}")
            return {mac: val["ip"] for mac, val in data.items() if mac != "timestamp"}
    except Exception as e:
        print(f"[!] Failed to read ARP file: {e}", flush=True)
        log_event(f"[!] ARP file error: {e}")
        return {}

def match_context(sniffed_data, scanned_data):
    context = {}

    scanned_hosts = scanned_data.get("results", scanned_data)
    sniffed_devices = sniffed_data.get("devices", sniffed_data)
    arp_map = load_latest_arp_map()

    for mac, dev in sniffed_devices.items():
        if not dev.get("ip") and mac in arp_map:
            ip_info = arp_map[mac]
            if isinstance(ip_info, dict):
                dev["ip"] = ip_info.get("ip")
            elif isinstance(ip_info, str):
                dev["ip"] = ip_info

    ip_to_mac = {
        dev.get("ip"): mac
        for mac, dev in sniffed_devices.items()
        if dev.get("ip")
    }

    for ip, details in scanned_hosts.items():
        raw_mac = details.get("mac")
        if not raw_mac and ip in ip_to_mac:
            raw_mac = ip_to_mac[ip]
        mac = raw_mac.lower() if raw_mac else None

        context[ip] = {
            "ip": ip,
            "hostname": details.get("hostname"),
            "state": details.get("state"),
            "protocols": details.get("protocols"),
            "mac": mac,
            "interface": details.get("interface"),
            "risk_level": details.get("risk_level"),
            "score": details.get("score"),
            "ssid": None,
            "vendor": details.get("vendor", "Unknown"),
            "seen": None,
            "packet_type": None
        }

        if mac and mac in sniffed_devices:
            dev = sniffed_devices[mac]
            context[ip].update({
                "ssid": dev.get("ssid"),
                "vendor": dev.get("vendor"),
                "seen": dev.get("last_seen") or dev.get("seen"),
                "packet_type": dev.get("packet_type")
            })

    return context

def run_context_builder():
    sniffed = load_latest_json(SNIFFER_DIR)
    scanned = load_latest_json(SCANNER_DIR)

    if not sniffed or not scanned:
        print("[!] Missing data. Cannot build context.", flush=True)
        log_event("[ERROR] Sniffed or scanned data missing. Aborted.")
        return

    combined = match_context(sniffed, scanned)

    gateway_ip = None
    for ip in combined.keys():
        if ipaddress.IPv4Address(ip).packed[-1] == 1:
            gateway_ip = ip
            break

    final_output = {
        "context_time": datetime.now().isoformat(),
        "device_count": len(sniffed.get("devices", {})),
        "matched_count": len(combined),
        "gateway": gateway_ip,
        "devices": combined
    }

    try:
        with open(OUTPUT_FILE, "w") as f:
            json.dump(final_output, f, indent=4)
        print(f"[✓] Context built successfully → {OUTPUT_FILE}", flush=True)
        print(f"[✓] Matched {len(combined)} devices.", flush=True)
        log_event(f"[SUCCESS] Context written to {OUTPUT_FILE} ({len(combined)} entries)")

        if gateway_ip:
            print(f"[✓] Gateway auto-detected: {gateway_ip}", flush=True)
            log_event(f"[✓] Gateway auto-detected and saved: {gateway_ip}")
        else:
            print("[!] Gateway not detected.", flush=True)
            log_event("[!] Gateway not detected.")
    except Exception as e:
        msg = f"[!] Failed to write context file: {e}"
        print(msg, flush=True)
        log_event(msg)

if __name__ == "__main__":
    run_context_builder()
