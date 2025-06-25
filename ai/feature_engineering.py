import json
import os
import csv

CONTEXT_FILE = "data/context/context.json"
OUT_CSV = "data/processed/ai_model_input.csv"
OUT_SUMMARY = "data/processed/feature_summary.json"
os.makedirs("data/processed", exist_ok=True)

def extract_features():
    with open(CONTEXT_FILE) as f:
        context = json.load(f)

    rows = []
    summaries = {}

    for ip, device in context.get("devices", {}).items():
        if ip.endswith(".1"):
            continue

        tcp = device.get("protocols", {}).get("tcp", [])
        udp = device.get("protocols", {}).get("udp", [])

        open_tcp = [p for p in tcp if p.get("state") == "open"]
        open_udp = [p for p in udp if p.get("state") == "open"]

        if not open_tcp and not open_udp:
            continue

        all_services = open_tcp + open_udp
        service_names = {s.get("name", "") for s in all_services if s.get("name")}
        service_ports = {s.get("port") for s in all_services if s.get("port") is not None}
        port_count = len(service_ports)

        row = {
            "ip": ip,
            "tcp_port_count": len(open_tcp),
            "udp_port_count": len(open_udp),
            "total_port_count": port_count,
            "unique_service_count": len(service_names),
            "vendor_risk_score": device.get("vendor_risk_score", 0.5),
            "is_gateway": 0
        }

        rows.append(row)

        summaries[ip] = {
            "features": row,
            "explanation": [
                f"{len(open_tcp)} open TCP port(s)",
                f"{len(open_udp)} open UDP port(s)",
                f"{len(service_names)} unique service(s)",
                f"Vendor risk score: {row['vendor_risk_score']}"
            ]
        }

    return rows, summaries

def save_outputs(rows, summaries):
    if not rows:
        print("[!] No open-port devices found. Exiting.", flush=True)
        return

    print("[~] Writing AI input CSV...", flush=True)
    with open(OUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"[✓] AI input CSV saved to: {OUT_CSV}", flush=True)

    print("[~] Writing feature summary JSON...", flush=True)
    with open(OUT_SUMMARY, "w") as f:
        json.dump(summaries, f, indent=4)
    print(f"[✓] Feature summary saved to: {OUT_SUMMARY}", flush=True)

    print("\n[✓] Included devices and their port info for AI:", flush=True)
    for row in rows:
        print(f" - {row['ip']}: {row['tcp_port_count']} TCP, {row['udp_port_count']} UDP, {row['unique_service_count']} service(s)", flush=True)

if __name__ == "__main__":
    rows, summaries = extract_features()
    save_outputs(rows, summaries)
