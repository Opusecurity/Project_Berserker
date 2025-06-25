import subprocess
import os
import sys
import time
import json
from datetime import datetime

LOG_FILE = "logs/launcher.log"
os.makedirs("logs", exist_ok=True)

def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")
    print(f"[~] {message}")

def run_step(name, command):
    log(f"Starting: {name}")
    start = time.perf_counter()
    try:
        if callable(command):
            command()
        else:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in process.stdout:
                log("    " + line.strip())
            process.wait()
            if process.returncode != 0:
                raise subprocess.CalledProcessError(process.returncode, command)
        duration = time.perf_counter() - start
        log(f"[✓] Completed: {name} in {duration:.2f} sec")
    except subprocess.CalledProcessError as e:
        log(f"[!] ERROR during {name}: {e}")
        sys.exit(1)

def auto_detect_wireless_interface():
    try:
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if line.strip().startswith("Interface"):
                return line.strip().split()[-1]
    except Exception as e:
        log(f"[!] Interface detection failed: {e}")
    return "wlan0"

def set_interface_mode(interface, mode):
    log(f"Switching {interface} to {mode} mode...")
    try:
        subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
        subprocess.run(["sudo", "iw", interface, "set", "type", mode], check=True)
        subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
        log(f"[✓] {interface} set to {mode} mode.")
    except subprocess.CalledProcessError as e:
        log(f"[!] Failed to set interface {interface} to {mode} mode: {e}")
        sys.exit(1)

def main():
    print("\n=== Project Berserker: Full Automatic Launcher ===\n")
    start_time = datetime.now().isoformat()
    wireless_interface = auto_detect_wireless_interface()

    steps = [
        ("Active Network Scan",           "python core/scanner.py"),
        ("Set Wireless Mode to Monitor",  lambda: set_interface_mode(wireless_interface, "monitor")),
        ("Passive Sniffing",              "python core/sniffer.py"),
        ("Restore Wireless Mode",         lambda: set_interface_mode(wireless_interface, "managed")),
        ("Active ARP Resolution",         "python core/arp_resolver.py"),
        ("Initial Context Build",         "python core/context_builder.py"),
        ("Feature Engineering",           "python ai/feature_engineering.py"),
        ("AI Model Training",             "python ai/train.py"),
        ("Strategy Selection",            "python ai/strategy_selector.py"),
        ("Brute-force Attacks",           "python core/brute_forces.py --delay 0.5"),
        ("SMB Share Enumeration",         "python core/smb_enum.py"),
        ("Web Application Attacks",       "python core/web_attack.py"),
        ("Man-in-the-Middle Attack",      "python3 core/mitm_attack.py"),
        ("Alias Mapper",                  "python core/alias_mapper.py"),
        ("MITM Analysis",                 "python core/mitm_analyze.py"),
        ("Generate Pentest Results",      "python core/pentest_results_generator.py"),
        ("Post-Attack Feature Eng.",      "python ai/feature_engineering_post_attack.py"),
        ("Post-Attack AI Training",       "python ai/train_post.py"),
        ("Post-Attack Target Ranking",    "python ai/target_ranker_post.py")
    ]

    for name, command in steps:
        run_step(name, command)

    end_time = datetime.now().isoformat()
    os.makedirs("data", exist_ok=True)
    with open("data/report_meta.json", "w") as f:
        json.dump({
            "start_time": start_time,
            "end_time": end_time
        }, f, indent=4)
    log("Report metadata file created.")

    run_step("Generate Final PDF Report", "python core/report_generator.py")

    log("[+] Final PDF report generated: reports/final_report.pdf")
    log("Full pipeline executed successfully.")
    log("ALL MODULES COMPLETED SUCCESSFULLY")

if __name__ == "__main__":
    main()
