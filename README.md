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
```powershell
mkdir C:\Temp -Force
Add-MpPreference -ExclusionPath C:\Temp
