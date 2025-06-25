import nmap
import json
import os
import netifaces
import socket
import multiprocessing
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from mac_vendor_lookup import MacLookup

OUTPUT_DIR = "data/raw/"
LOG_FILE = "logs/scanner_errors.log"
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs("logs", exist_ok=True)

mac_lookup = MacLookup()
try:
    mac_lookup.load_vendors()
except Exception as e:
    with open(LOG_FILE, "a") as logf:
        logf.write(f"[{datetime.now()}] Error loading MAC vendor DB: {e}\n")

def netmask_to_cidr(netmask):
    return sum(bin(int(octet)).count('1') for octet in netmask.split('.'))

def get_all_subnets():
    subnets = []
    interfaces = netifaces.interfaces()

    for interface in interfaces:
        try:
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                ipv4_info = addrs[netifaces.AF_INET][0]
                ip = ipv4_info.get("addr")
                netmask = ipv4_info.get("netmask")
                if ip and netmask and not ip.startswith("127."):
                    cidr = netmask_to_cidr(netmask)
                    subnet = f"{ip}/{cidr}"
                    subnets.append((interface, subnet))
        except Exception as e:
            with open(LOG_FILE, "a") as logf:
                logf.write(f"[{datetime.now()}] Interface error on {interface}: {e}\n")
            continue

    return subnets

def dns_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ""

def scan_single_host(host):
    try:
        nm = nmap.PortScanner()
        print(f"[*] Scanning host: {host}", flush=True)
        nm.scan(hosts=host, arguments='-p 21,22,80,443,445,3389 -sS -sU -sV -T4')

        if host not in nm.all_hosts():
            print(f"[!] Host {host} returned no results.", flush=True)
            return None

        addresses = nm[host].get('addresses', {})
        mac = addresses.get('mac', None)
        try:
            vendor = mac_lookup.lookup(mac) if mac else "Unknown"
        except:
            vendor = "Unknown"

        tcp_ports = nm[host].get("tcp", {})
        filtered_count = sum(1 for p in tcp_ports if tcp_ports[p]["state"] == "filtered")
        total_ports = len(tcp_ports)
        risk_ratio = filtered_count / max(total_ports, 1)
        risk_level = "high" if risk_ratio > 0.5 else "normal"
        score = round(1.0 - risk_ratio, 2)

        host_info = {
            "hostname": dns_lookup(host),
            "state": nm[host].state(),
            "protocols": {},
            "mac": mac.lower() if mac else None,
            "vendor": vendor,
            "risk_level": risk_level,
            "score": score
        }

        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            host_info["protocols"][proto] = []

            for port in ports:
                port_data = nm[host][proto][port]
                host_info["protocols"][proto].append({
                    "port": port,
                    "state": port_data.get("state", ""),
                    "name": port_data.get("name", ""),
                    "product": port_data.get("product", ""),
                    "version": port_data.get("version", ""),
                    "extrainfo": port_data.get("extrainfo", "")
                })

        print(f"[✓] Host {host} scanned. Protocols: {list(host_info['protocols'].keys())}", flush=True)
        return host, host_info

    except Exception as e:
        with open(LOG_FILE, "a") as logf:
            logf.write(f"[{datetime.now()}] Error scanning {host}: {e}\n")
        return None

def get_safe_thread_count():
    cpu_threads = multiprocessing.cpu_count()
    calculated_threads = cpu_threads * 4

    if calculated_threads > 256:
        print(f"[!] {calculated_threads} threads detected. Limiting to 256 for stability.", flush=True)
        return 256
    else:
        return calculated_threads

def scan_subnet_parallel(subnet, interface):
    print(f"[+] Discovering live hosts in subnet: {subnet}", flush=True)
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments='-sn')

    hosts = nm.all_hosts()
    print(f"[+] {len(hosts)} host(s) found on {interface}", flush=True)

    results = {}
    max_threads = get_safe_thread_count()

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_single_host, host): host for host in hosts}
        for future in as_completed(futures):
            result = future.result()
            if result:
                ip, info = result
                info["interface"] = interface
                results[ip] = info

    print(f"[✓] Finished scanning subnet {subnet}", flush=True)
    return results

def full_network_scan():
    print("[*] Starting full network scan...", flush=True)
    all_results = {}
    subnets = get_all_subnets()
    scan_time = datetime.now().isoformat()

    if not subnets:
        print("[!] No valid subnets found.", flush=True)
        return

    for interface, subnet in subnets:
        print(f"\n[~] Interface: {interface} → Subnet: {subnet}", flush=True)
        result = scan_subnet_parallel(subnet, interface)
        all_results.update(result)
        print(f"[~] Total hosts scanned so far: {len(all_results)}", flush=True)

    if not all_results:
        print("[!] Scan completed but no active hosts were discovered.", flush=True)
        return

    timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M")
    filename = os.path.join(OUTPUT_DIR, f"scan_{timestamp}.json")

    final_output = {
        "scan_time": scan_time,
        "host_count": len(all_results),
        "results": all_results
    }

    print(f"[~] Writing results to: {filename}", flush=True)

    with open(filename, "w") as f:
        json.dump(final_output, f, indent=4)

    print(f"\n[✓] Network scan complete. {len(all_results)} host(s) discovered.", flush=True)

if __name__ == "__main__":
    full_network_scan()
