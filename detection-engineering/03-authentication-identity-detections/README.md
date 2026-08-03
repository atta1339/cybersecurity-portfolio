# Project 03: Authentication & Identity Threat Detection

## Executive Summary
This project focuses on identifying identity-based attacks within Windows environments using native Security Event Logs in Splunk. It breaks down two core attack patterns: Brute Force password guessing and explicit credential abuse (Pass-the-Hash / RunAs).

---

## Key Windows Event IDs & Concepts

* **Event ID 4625**: Failed logon attempt (wrong password or username).
* **Event ID 4624**: Successful logon.
  * **Logon Type 2**: Interactive (physical keyboard).
  * **Logon Type 3**: Network connection (SMB/RPC shares).
  * **Logon Type 9**: `NewCredentials` (often used in `runas /netonly` or Pass-the-Hash moves).

---

## Threat Scenarios & SPL Logic

### Scenario 1: Brute Force Followed by Successful Logon
Detects high-frequency logon failures from a single IP address followed by a successful login, indicating a cracked password.

**Splunk SPL Query:**
```spl
index=win_events EventCode IN (4625, 4624)
| stats 
    count(eval(EventCode=4625)) as Failed_Logons, 
    count(eval(EventCode=4624)) as Successful_Logons
    by Source_Network_Address, TargetUserName
| where Failed_Logons >= 5 AND Successful_Logons > 0
| eval Alert_Severity="High"
