# Project Berserker

AI-Powered Autonomous Penetration Testing Framework for Corporate Networks

Project Berserker is a fully automated and modular penetration testing framework designed to identify vulnerabilities in corporate networks using artificial intelligence. It performs network reconnaissance, contextual analysis, dynamic attack planning, and post-attack risk evaluation with no manual intervention required.

## Features

- End-to-end automation
- AI-powered pre/post attack analysis
- Dynamic strategy selection per host
- Multi-protocol brute-force (SSH, FTP, SMB)
- Web vulnerability scanning (SQLi, XSS, LFI)
- MITM traffic interception & content extraction
- PDF reporting with risk ranking
- GUI interface for full control

## Modules

### Reconnaissance

- `scanner.py`: Full port and service scanning (TCP/UDP)
- `sniffer.py`: Passive 802.11 wireless traffic analysis
- `arp_resolver.py`: ARP and DNS-based IP/MAC/hostname mapping

### Context Building and AI

- `context_builder.py`: Merges all discovery data
- `feature_engineering.py`: Extracts pre-attack features
- `train.py`: Trains ML model to estimate risk level
- `strategy_selector.py`: Selects attack modules dynamically

### Autonomous Attacks

- `brute_forces.py`: FTP, SSH, and SMB brute-force attacks
- `smb_enum.py`: SMB share enumeration
- `web_attack.py`: SQLi, XSS, and LFI tests on discovered forms
- `mitm_attack.py`: Bettercap-based MITM attack
- `alias_mapper.py` and `mitm_analyze.py`: Traffic analysis and alias-IP matching

### Post-Attack Analysis

- `pentest_results_generator.py`: Aggregates all attack results
- `feature_engineering_post_attack.py`: Post-exploitation feature extraction
- `train_post.py`: Trains post-attack risk model
- `target_ranker_post.py`: Ranks devices based on real-world exploitability

### Reporting and GUI

- `report_generator.py`: Generates final PDF report
- `launcher.py`: Executes all modules in order
- `gui/`: PyQt6 GUI interface for full graphical interaction

## License
This project is licensed under the GNU Affero General Public License v3.0.  
See the [LICENSE](./LICENSE) file for more details.

## Disclaimer
This tool is intended for educational and authorized use only.  
Unauthorized use against systems without permission is strictly prohibited and illegal.
