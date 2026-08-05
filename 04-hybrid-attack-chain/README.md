# 04. End-to-End Hybrid Attack Chain Detection (Phishing to Persistence)

## Executive Summary
This module documents the detection engineering lifecycle for a multi-stage intrusion sequence on Windows endpoints. The scenario models an initial access vector via a weaponised email attachment spawning malicious child processes, followed by obfuscated PowerShell execution, payload staging, and local persistence establishment through Scheduled Tasks.

By correlating **Sysmon Process Creation**, **PowerShell ScriptBlock Logging**, and **Windows Security Event Logs** in Splunk Enterprise, this project delivers both single-stage detection queries and a multi-event correlation rule for high-confidence SOC alerting.

---

## Technical Stack & Telemetry Sources
* **SIEM & Analytics:** Splunk Enterprise (SPL)
* **Endpoint Telemetry:** 
  * Windows Sysmon (`Event ID 1`: Process Creation)
  * Windows PowerShell (`Event ID 4104`: ScriptBlock Logging)
  * Windows Security Log (`Event ID 4698`: Scheduled Task Created)
* **Threat Frameworks:** MITRE ATT&CK Matrix

---

## MITRE ATT&CK Mapping

| Attack Phase | Technique | ID | Target Telemetry |
| :--- | :--- | :--- | :--- |
| **Initial Access** | Phishing: Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Sysmon Event ID 1 |
| **Execution** | Command & Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell Event ID 4104 |
| **Persistence** | Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Security Event ID 4698 / Sysmon Event ID 1 |

---

## Intrusion Architecture & Attack Chain

```text
[ Stage 1: Initial Access ]          [ Stage 2: Script Execution ]        [ Stage 3: Persistence ]
   winword.exe / excel.exe                 powershell.exe -enc ...            schtasks.exe /create
             │                                       │                                  │
             ▼                                       ▼                                  ▼
   Sysmon Event ID 1                      PowerShell Event ID 4104              Security Event ID 4698
(Malicious Parent-Child)                  (Obfuscated ScriptBlock)             (Anomalous Task Scheduled)
| Project | Description | Target Telemetry | Key Focus |
| :--- | :--- | :--- | :--- |
| **[04. Hybrid Attack Chain](./04-hybrid-attack-chain)** | Multi-stage correlation linking phishing initial access, obfuscated execution, and scheduled task persistence. | Sysmon (EID 1), PowerShell (EID 4104), Windows Security (EID 4698) | SPL Attack Chain Correlation & Detection Engineering |
