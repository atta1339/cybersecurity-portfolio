# 🛡️ Cybersecurity & Detection Engineering Portfolio

Welcome to my central cybersecurity portfolio repository. This repository showcases hands-on detection engineering projects, SIEM analytics (Splunk SPL), telemetry configurations, and threat hunting workflows mapped to the **MITRE ATT&CK Framework**.

---

## 📁 Detection Engineering Projects

| Project | Target Telemetry | Key Focus & Techniques | MITRE ATT&CK Mapping |
| :--- | :--- | :--- | :--- |
| **[01. Parent-Child LOLBin Detection](./detection-engineering/01-parent-child-lolbin-detection)** | Windows Sysmon (Event ID 1) | Process creation monitoring, LOLBin execution (`powershell.exe`/`cmd.exe`), dynamic risk scoring for encoded commands. | [T1059](https://attack.mitre.org/techniques/T1059/), [T1036](https://attack.mitre.org/techniques/T1036/) |
| **[02. Web Attack Analysis & Detection](./detection-engineering/02-web-attack-analysis-detection)** | Web Access Logs (`access_combined`) | Detecting SQL Injection (SQLi), Directory Traversal (LFI), and automated vulnerability scanners (Nikto/Gobuster). | [TA0001](https://attack.mitre.org/tactics/TA0001/), [T1190](https://attack.mitre.org/techniques/T1190/) |

---

## 🛠️ Technical Stack & Tooling
* **SIEM & Analytics**: Splunk Enterprise (SPL)
* **Endpoint Telemetry**: Windows Sysmon, Event Viewer
* **Web & Network Telemetry**: Nginx/Apache Web Logs
* **Threat Frameworks**: MITRE ATT&CK, OWASP Top 10
* **Documentation & Version Control**: Git, GitHub, Markdown
