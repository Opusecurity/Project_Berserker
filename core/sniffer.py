import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import sniff, Dot11, Dot11Elt, RadioTap, get_if_list
from datetime import datetime
from mac_vendor_lookup import MacLookup
import os
import json
import subprocess

OUTPUT_DIR = "data/sniffed/"
LOG_FILE = "logs/sniffer_errors.log"
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs("logs", exist_ok=True)

detected_devices = {}
mac_lookup = MacLookup()

try:
    mac_lookup.load_vendors()
except Exception as e:
    with open(LOG_FILE, "a") as logf:
        logf.write(f"[{datetime.now()}] Failed to load MAC vendor DB: {e}\n")

def get_packet_type(pkt):
    if pkt.type == 0:
        return {
            0: "Association Request",
            1: "Association Response",
            4: "Probe Request",
            5: "Probe Response",
            8: "Beacon"
        }.get(pkt.subtype, "Management")
    elif pkt.type == 1:
        return "Control"
    elif pkt.type == 2:
        return "Data"
    return "Unknown"

def extract_channel(pkt):
    if pkt.haslayer(Dot11Elt):
        elt = pkt[Dot11Elt]
        while isinstance(elt, Dot11Elt):
            if elt.ID == 3:
                return int.from_bytes(elt.info, byteorder='little')
            elt = elt.payload
    return None

def extract_frequency(pkt):
    if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], 'ChannelFrequency'):
        return pkt[RadioTap].ChannelFrequency
    return None

def packet_handler(pkt):
    mac_fields = set()

    for attr in ["addr1", "addr2", "addr3"]:
        mac = getattr(pkt, attr, None)
        if mac and mac != "ff:ff:ff:ff:ff:ff":
            mac_fields.add(mac.lower())

    for mac in mac_fields:
        if mac not in detected_devices:
            try:
                vendor = mac_lookup.lookup(mac)
            except Exception as e:
                vendor = "Unknown"
                with open(LOG_FILE, "a") as logf:
                    logf.write(f"[{datetime.now()}] Vendor lookup failed for {mac}: {e}\n")

            ssid = None
            if pkt.haslayer(Dot11Elt) and hasattr(pkt, "addr2") and mac == pkt.addr2.lower():
                try:
                    ssid = pkt[Dot11Elt].info.decode(errors="ignore")
                except:
                    ssid = None

            packet_type = get_packet_type(pkt)
            signal_strength = getattr(pkt, "dBm_AntSignal", None)
            channel = extract_channel(pkt)
            frequency = extract_frequency(pkt)

            detected_devices[mac] = {
                "ssid": ssid,
                "bssid": pkt.addr3.lower() if pkt.addr3 else None,
                "vendor": vendor,
                "packet_type": packet_type,
                "signal_strength": signal_strength,
                "channel": channel,
                "frequency": frequency,
                "seen_count": 1,
                "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

            print(f"[+] Detected MAC={mac} | SSID={ssid or 'Hidden'} | Vendor={vendor} | Type={packet_type}", flush=True)
        else:
            detected_devices[mac]["seen_count"] += 1
            detected_devices[mac]["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def auto_detect_monitor_interface():
    try:
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        current_iface = None
        monitor_ifaces = []

        for line in lines:
            line = line.strip()
            if line.startswith("Interface"):
                current_iface = line.split()[-1]
            elif line.startswith("type") and "monitor" in line and current_iface:
                monitor_ifaces.append(current_iface)

        if monitor_ifaces:
            return monitor_ifaces[0]
    except Exception as e:
        with open(LOG_FILE, "a") as logf:
            logf.write(f"[{datetime.now()}] Monitor interface detection failed (iw): {e}\n")

    for iface in get_if_list():
        if "mon" in iface:
            return iface
    for iface in get_if_list():
        if iface.startswith("wlan"):
            return iface
    return "wlan0mon"

def start_sniff(interface="wlan0mon", duration=60, packet_count=0):
    print(f"[*] Starting sniff session...", flush=True)
    print(f"[~] Sniffing on interface: {interface} (passive mode)...", flush=True)

    try:
        sniff(iface=interface, prn=packet_handler, count=packet_count, timeout=duration, store=0)
    except PermissionError:
        print("[!] Error: You must run this script with sudo/root.", flush=True)
        return
    except Exception as e:
        print(f"[!] Unexpected error: {e}", flush=True)
        with open(LOG_FILE, "a") as logf:
            logf.write(f"[{datetime.now()}] Unexpected sniffing error: {e}\n")
        return

    timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M")
    filename = os.path.join(OUTPUT_DIR, f"sniff_{timestamp}.json")

    final_output = {
        "scan_time": datetime.now().isoformat(),
        "device_count": len(detected_devices),
        "devices": detected_devices
    }

    print(f"[~] Writing sniff results to file...", flush=True)

    with open(filename, "w") as f:
        json.dump(final_output, f, indent=4)

    print(f"[✓] Sniffing complete. {len(detected_devices)} unique device(s) found.", flush=True)
    print(f"[→] Results saved to: {filename}", flush=True)

if __name__ == "__main__":
    interface = auto_detect_monitor_interface()
    start_sniff(interface)
