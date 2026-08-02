# Project 03: Authentication & Identity Threat Detection

## Executive Summary
This project focuses on detecting authentication anomalies and identity-based attacks within Active Directory and Windows environments using native Windows Security Event telemetry in Splunk. It targets initial access and lateral movement techniques, specifically high-frequency brute force attempts followed by successful compromise, and explicit credential abuse (Pass-the-Hash / RunAs).

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Telemetry Source |
| :--- | :--- | :--- | :--- |
| **Credential Access** | [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | `WinEventLog:Security` (4625, 4624) |
| **Defense Evasion / Lateral Movement** | [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | Pass the Hash | `WinEventLog:Security` (4624 - Type 9) |

---

## Monitored Event IDs

* **Event ID 4625**: An account failed to log on.
* **Event ID 4624**: An account was successfully logged on.
  * **Logon Type 3**: Network logon (SMB/RPC).
  * **Logon Type 9**: `NewCredentials` (often associated with `runas /netonly` or Pass-the-Hash techniques).

---

## Detection Scenarios & SPL Logic

### Scenario 1: Brute Force Followed by Successful Logon (T1110)
Detects multiple failed logon attempts (`4625`) from a single source IP targeting a user, immediately followed by a successful logon (`4624`).

**Splunk SPL Query:**
```spl
index=win_events EventCode IN (4625, 4624)
| stats 
    count(eval(EventCode=4625)) as Failed_Logons, 
    count(eval(EventCode=4624)) as Successful_Logons, 
    values(WorkstationName) as Source_Workstation 
    by Source_Network_Address, Target_Account_Name
| where Failed_Logons >= 5 AND Successful_Logons > 0
| eval Alert_Severity="High"
