# Detection Project: Suspicious Parent-Child Process Execution (LOLBins)

## 📌 Threat Context & Overview
Attacking vectors frequently utilize spear-phishing attachments or compromised web browsers to deliver malicious payloads. Once executed, these applications often spawn command interpreters or Living-off-the-Land Binaries (LOLBins) like `powershell.exe` or `cmd.exe` to execute secondary payloads or perform system discovery.

This project implements an end-to-end detection pipeline targeting these execution patterns using **Sysmon** telemetry and **Splunk Enterprise**.

* **MITRE ATT&CK Mapping**:
  * **Tactics**: Execution ([TA0002](https://attack.mitre.org/tactics/TA0002/)), Defense Evasion ([TA0005](https://attack.mitre.org/tactics/TA0005/))
  * **Techniques**: Command and Scripting Interpreter ([T1059](https://attack.mitre.org/techniques/T1059/)), Masquerading ([T1036](https://attack.mitre.org/techniques/T1036/))
* **Target Telemetry**: Sysmon Event ID 1 (Process Creation)

---

## 🛠️ Infrastructure & Telemetry Setup

1. **Sysmon Deployment**: Configured Sysmon on the endpoint using a custom XML rule set designed to isolate process creation events (`EventID 1`) for key command line interpreters.
2. **Configuration File**: Located in [`configs/sysmonconfig.xml`](./configs/sysmonconfig.xml).
3. **Verification**: Verified active event capture in Windows Event Viewer under `Microsoft-Windows-Sysmon/Operational`.

![Sysmon Event Viewer Verification](./docs/screenshots/event_viewer_sysmon.png)

---

## 🔍 Splunk Analytics (SPL)

The detection logic extracts the parent and child process names, checks against high-risk parent-child pairs (e.g., Office applications, browsers, or PDF viewers spawning shell binaries), and assigns dynamic risk scoring based on common defense evasion flags (e.g., encoded commands, bypass flags).

**Detections Query**:
```splunk
index=* EventID=1
| eval ParentProcess=mvindex(split(ParentImage, "\\"), -1),
       ChildProcess=mvindex(split(Image, "\\"), -1)
| where match(ParentProcess, "(?i)(winword\.exe|excel\.exe|powerpnt\.exe|outlook\.exe|chrome\.exe|msedge\.exe|acrord32\.exe)")
  AND match(ChildProcess, "(?i)(powershell\.exe|cmd\.exe|wmic\.exe|mshta\.exe|certutil\.exe|cscript\.exe|wscript\.exe)")
| eval RiskLevel=if(match(CommandLine, "(?i)(-e|-enc|-encodedcommand|bypass|-nop|-noni|downloadstring|iex)"), "High (Encoded/Evasive Flag)", "Medium (Unusual Parent-Child Execution)")
| stats count min(_time) as first_seen max(_time) as last_seen by Computer User ParentProcess ChildProcess CommandLine RiskLevel
| convert ctime(first_seen) ctime(last_seen)