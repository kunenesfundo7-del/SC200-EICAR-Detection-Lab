# SC200 - Custom Detection for EICAR Malware Simulation

## Tools
- Microsoft Defender XDR
- Microsoft Sentinel
- KQL
- MITRE ATT&CK - T1204.002

## What I Did

### 1. Prepare Lab Environment
mkdir C:\Temp -Force

Add-MpPreference -ExclusionPath C:\Temp

Isolated folder to prevent auto-delete.

### 2. Analytics Rule
Rule Name: SC200 - EICAR Detection - Sfundo

Frequency: Every 1 Hour

KQL: DeviceFileEvents | where FileName == "EICAR.txt"

### 3. Execute Simulation
notepad C:\Temp\EICAR.txt

Content: X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*

### 4. Investigation
DeviceFileEvents | where FileName == "EICAR.txt"

### 5. Cleanup
Remove-Item C:\Temp\EICAR.txt -Force

Author: Sfundo | Aspiring SOC Analyst
