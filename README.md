<img width="657" height="987" alt="image" src="https://github.com/user-attachments/assets/bd911183-b512-4165-b24d-64fd7c8ad53a" />

## Executive Summary
- Incident Report: Bridge Takeover & Data Exfiltration
- Incident ID: INC-2025-12-23-AZUKI
- Date: January 30, 2026
- Analyst:

## Incident Overview
This report provides a breakdown of the Advanced Persistent Threat (APT) breach detected at Azuki Import/Export in November 2025. The attackers established a foothold on November 19, then paused for three days. They resurfaced on November 22 with an attack geared towards moving laterally across the network and stealing user credentials.

This report documents the complete attack chain through Microsoft Defender for Endpoint telemetry analysis, utilizing Kusto Query Language (KQL) to identify Indicators of Compromise (IOCs) and Tactics, Techniques, and Procedures (TTPs) aligned with the MITRE ATT&CK framework.

## INVESTIGATION METHODOLOGY
* Data Sources:
- Microsoft Defender for Endpoint Logs
- DeviceLogonEvents
- DeviceProcessEvents
- DeviceFileEvents
- DeviceRegistryEvents
- Analysis Period: November 19 - 25, 2025

Query Language: Kusto Query Language (KQL)

Framework: MITRE ATT&CK


## Technical Analysis
Affected Systems & Data:

- Target System: `azuki-adminpc` (CEO/Administrative Workstation).
- Compromised Accounts: `yuki.tanaka` (Primary Victim), `yuki.tanaka2` (Backdoor Account).

## Exfiltrated Data:
- Financial Records: Banking, QuickBooks, Tax, and Contract records.
- Credentials: Azuki-Passwords.kdbx (KeePass database), OLD-Passwords.txt (Plaintext), and Google Chrome Login Data.

## Indicators of Compromise (IoCs)
IPv4 Addresses:
- 10.1.0.204 (Internal Lateral Movement Source).
- 45.112.123.227 (Exfiltration Destination - gofile.io).</br>
Domains:
- litter.catbox.moe (Malware Hosting).
- store1.gofile.io (Exfiltration).</br>
Filenames:
- meterpreter.exe (C2 Implant).
- m.exe (Renamed Mimikatz).
- KB5044273-x64.7z (Malicious Payload masquerading as Update).
- Named Pipe: \Device\NamedPipe\msf-pipe-5902.



## MITRE ATT&CK MAPPING

| Tactic           | Technique   | Procedure |
| -------------    |:-----------:| :--------:|
Initial Access	   | T1078	     |  Valid Accounts - Compromised credentials used for RDP access
Lateral Movement   | T1021.001	 |  Remote Desktop Protocol - mstsc.exe to file server
Discovery          | T1135	     |  Network Share Discovery - net.exe enumeration
Discovery	         | T1033	     |  System Owner/User Discovery - whoami.exe execution
Discovery	         | T1016	     |  System Network Configuration - ipconfig.exe execution
Defense Evasion    | T1105	     |  Ingress Tool Transfer - certutil.exe downloads
Defense Evasion    | T1036.003	 |  Masquerading - Renamed credential dumping tools
Collection	       | T1005	     |  Data from Local System - CSV/XLSX file creation
Collection	       | T1074.001	 |  Local Data Staging - robocopy.exe operations
Collection	       | T1560.001	 |  Archive via Utility - 7z.exe compression
Credential Access  | T1003.001	 |  LSASS Memory Dumping - Credential theft
Exfiltration	     | T1041	     |  Exfiltration Over C2 - curl.exe uploads
Exfiltration	     | T1567.002	 |  Cloud Storage Exfiltration - Cloud service uploads
Persistence	       | T1547.001	 |  Registry Run Keys - Autostart mechanism
Defense Evasion    | 	T1070.004	 |  File Deletion - History file removal


## Impact Analysis
- Confidentiality (Critical): Loss of sensitive financial data (banking/tax records), master passwords (Azuki-Passwords.kdbx), and browser-stored credentials.
- Integrity (High): System integrity compromised via the creation of backdoor administrative accounts and the modification of system groups.
- Availability (Low): No ransomware or destructive wiping was observed; operations were not halted.


## Key Evidence Requiring Deeper Analysis

## Lessons Learned

## Threat Actor Assessment








## Attack Timeline

## Flag 1:
'''kql

'''
## Flag 2:
## Flag 3:
## Flag 4:
## Flag 5:
## Flag 6:
## Flag 7:
## Flag 8:
## Flag 8:
## Flag 10:
## Flag 11:
## Flag 12:
## Flag 13:
## Flag 14:
## Flag 15:
## Flag 16:
## Flag 17:
## Flag 18:
## Flag 19: 
## Flag 20: 






























