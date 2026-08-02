# Detection Project: Web Application Attack Analysis & Detection

## 📌 Threat Context & Overview
Web applications are continuously targeted by automated scanners and malicious actors seeking initial access or sensitive data exposure. Common attack vectors include **SQL Injection (SQLi)**, **Path Traversal / Local File Inclusion (LFI)**, and **Insecure Direct Object Reference (IDOR)** exploitation.

This project establishes an end-to-end web detection baseline by analyzing web server access logs using **Splunk Enterprise** to identify reconnaissance, exploit attempts, and successful web application compromises.

* **MITRE ATT&CK Mapping**:
  * **Tactics**: Initial Access ([TA0001](https://attack.mitre.org/tactics/TA0001/)), Evasion ([TA0005](https://attack.mitre.org/tactics/TA0005/))
  * **Techniques**: Exploit Public-Facing Application ([T1190](https://attack.mitre.org/techniques/T1190/))
* **Target Telemetry**: Web Server Access Logs (`access_combined` format)

---

## 🔍 Attack Scenarios & Detection Logic

### Scenario 1: SQL Injection (SQLi) Probing & Exploitation
Attackers attempt to manipulate database queries via input parameters (`UNION SELECT`, `' OR 1=1`).

```spl
index=web_logs sourcetype=access_combined
| eval uri_decoded=urldecode(uri_path)
| regex uri_decoded="(?i)(union\s+select|select\s+.*\s+from|or\s+1=1|--|drop\s+table)"
| stats count by src_ip, uri_decoded, status, useragent
| sort - count
