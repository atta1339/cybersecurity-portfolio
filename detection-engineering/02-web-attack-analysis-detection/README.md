# Detection Project: Web Application Attack Analysis & Detection

## 📌 Threat Context & Overview
Web applications are continuously targeted by automated scanners and malicious actors seeking initial access or sensitive data exposure. Common attack vectors include **SQL Injection (SQLi)**, **Path Traversal / Local File Inclusion (LFI)**, and **Insecure Direct Object Reference (IDOR)** exploitation.

This project establishes an end-to-end web detection baseline by analysing web server access logs using **Splunk Enterprise** to identify reconnaissance, exploit attempts, and successful web application compromises.

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
### Scenario 2: Path Traversal / Local File Inclusion (LFI)
Attackers attempt to traverse directories using `../` sequences to access sensitive system files like `/etc/passwd` or `win.ini`.

```spl
index=web_logs sourcetype=access_combined
| eval uri_decoded=urldecode(uri_path)
| regex uri_decoded="(?i)(\.\.\/|\.\.\\|etc\/passwd|win\.ini)"
| stats count by src_ip, uri_decoded, status
| sort - count
index=web_logs sourcetype=access_combined status>=400
| stats count as failed_requests, count(eval(status=404)) as count_404 by src_ip, useragent
| where failed_requests > 3 or match(useragent, "(?i)(nikto|gobuster|acunetix|sqlmap)")
| sort - failed_requests
### 📸 Detection Proof
![Splunk SQLi Detection Proof](./assets/splunk_sqli_detection.png)
