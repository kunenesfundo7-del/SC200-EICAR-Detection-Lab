# SC200 - Custom Detection for EICAR Malware Simulation | Microsoft Defender XDR + Sentinel

## 🎯 Objective
Simulate a real malware execution using the EICAR test file and build an end-to-end detection & response workflow in Microsoft Defender XDR, as per SC-200 requirements.

## 🛠️ Tools & Technologies
- Microsoft Defender XDR (MDE, MDI)
- Microsoft Sentinel - Analytics Rules
- KQL - Advanced Hunting
- MITRE ATT&CK - T1204.002 (Malicious File)
- Virtual Lab VM - Windows 10/11 with Defender

## 🔍 Scenario
A user downloaded and created a known malicious test file `EICAR.txt`. Goal: Detect, Alert, and Investigate before it spreads.

## ⚙️ What I Did

### 1. Prepare Lab Environment

mkdir C:\Temp -Force
Add-MpPreference -ExclusionPath C:\Temp

Created isolated folder to prevent real-time protection from auto-deleting file before detection logic triggers - key SOC evasion consideration.

### 2. Create Custom Analytics Rule in Sentinel

**Rule Name:** SC200 - EICAR Detection - Sfundo

**Frequency:** Every 1 Hour

**KQL Query:**
**Alert:** Medium Severity - `EICAR file detected`
**Incident Creation:** Enabled - Group alerts into single incident

### 3. Execute Malware Simulation

notepad C:\Temp\EICAR.txt
# Content: X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*

dir C:\Temp
# Length 68 bytes - confirmed
DeviceFileEvents | where FileName == "EICAR.txt"
DeviceProcessEvents | where InitiatingProcessFileName == "notepad.exe"

Remove-Item C:\Temp\EICAR.txt -Force
Remove-MpPreference -ExclusionPath C:\Temp

