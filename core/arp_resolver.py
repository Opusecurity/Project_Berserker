import os
import json
import subprocess
import socket
from datetime import datetime
from scapy.all import ARP, Ether, srp

OUTPUT_DIR = "data/arp/"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def get_active_interface():
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "default via" in line and "dev" in line:
                return line.split("dev")[1].split()[0]
    except Exception as e:
        print(f"[!] Failed to get active interface: {e}", flush=True)
    return None

def get_interface_subnet(interface):
    try:
        result = subprocess.run(["ip", "-4", "addr", "show", interface], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1]
    except Exception as e:
        print(f"[!] Failed to get subnet for {interface}: {e}", flush=True)
    return None

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ""

def active_arp_scan(subnet, timeout=2):
    print(f"[*] Starting active ARP scan: {subnet}", flush=True)
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
        timeout=timeout,
        verbose=0
    )

    result = {}
    for _, received in ans:
        ip = received.psrc
        mac = received.hwsrc.lower()
        hostname = resolve_hostname(ip)
        result[mac] = {
            "ip": ip,
            "hostname": hostname
        }
        print(f"[+] {ip} ↔ {mac} | Hostname: {hostname or 'None'}", flush=True)
    return result

def save_arp_data(data):
    timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M")
    filename = os.path.join(OUTPUT_DIR, f"arp_{timestamp}.json")
    print(f"[~] Writing ARP mapping to: {filename}", flush=True)
    with open(filename, "w") as f:
        json.dump({"timestamp": timestamp, "arp_map": data}, f, indent=4)
    print(f"[✓] ARP + Hostname data saved successfully.", flush=True)

if __name__ == "__main__":
    iface = get_active_interface()
    if not iface:
        print("[X] No active network interface found. Exiting.", flush=True)
        exit(1)

    subnet = get_interface_subnet(iface)
    if not subnet:
        print(f"[X] Failed to get subnet for interface {iface}. Exiting.", flush=True)
        exit(1)

    arp_data = active_arp_scan(subnet)
    save_arp_data(arp_data)
