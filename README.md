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

## Attack Timeline

## Flag 1:
```kql
DeviceLogonEvents
| where DeviceName contains "azuki"
| where LogonType == "RemoteInteractive"
| project Timestamp, DeviceName, AccountName, RemoteIP, RemoteDeviceName
| sort by Timestamp desc
```

## Flag 2:
```kql
DeviceNetworkEvents
| where DeviceName contains "azuki-adminpc"
| where RemoteUrl !endswith "microsoft.com" and RemoteUrl !endswith "windowsupdate.com"
| where RemoteUrl != ""
| where InitiatingProcessFileName contains "curl"
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName, ProcessCommandLine
| sort by Timestamp asc
```

## Flag 3:
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine has_any ("7z", "7za", "winrar", "unzip", "expand")
| project Timestamp, FileName, ProcessCommandLine, AccountName
| sort by Timestamp asc
```

## Flag 4:
```kql
DeviceFileEvents
| where DeviceName == "azuki-adminpc"
| where InitiatingProcessFileName == "7z.exe"
| project Timestamp, FileName, FolderPath, SHA256, InitiatingProcessCommandLine
```

## Flag 5:
```kql
DeviceEvents
| where ActionType == "NamedPipeEvent"
| where Timestamp >= datetime(2025-11-24T23:20:00Z)
| extend Prop = parse_json(AdditionalFields)
| extend PipeName = tostring(Prop.PipeName)
| project Timestamp, DeviceName, ActionType, PipeName, InitiatingProcessFileName, AdditionalFields
| sort by Timestamp asc
```
## Flag 6:
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "-e ")
| project Timestamp, FileName, ProcessCommandLine, AccountName
| sort by Timestamp asc
```

## Flag 7:
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where FileName has_any ("qwinsta.exe", "rwinsta.exe", "query.exe", "net.exe", "quser.exe")
| project Timestamp, FileName, ProcessCommandLine, AccountName, AccountDomain
| sort by Timestamp asc
```

## Flag 8:
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine has_any ("trust", "domain_trusts", "all_trusts", "trustedDomain")
| project Timestamp, FileName, ProcessCommandLine, AccountName
| sort by Timestamp asc
```

## Flag 9:
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where FileName in~ ("netstat.exe", "arp.exe", "ipconfig.exe", "nbtstat.exe")
| project Timestamp, FileName, ProcessCommandLine, AccountName
| sort by Timestamp asc
```

## Flag 10:
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine contains "Azuki-Passwords.kdbx" or ProcessCommandLine contains "*.kdbx"
| project Timestamp, FileName, ProcessCommandLine, AccountName
```

## Flag 11:
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine has_any ("type", "findstr", "notepad", "more")
| where ProcessCommandLine has_any (".txt", ".lnk", "pass", "cred")
| project Timestamp, FileName, ProcessCommandLine, AccountName
| sort by Timestamp asc
```

## Flag 12:
```kql
DeviceFileEvents
| where DeviceName == "azuki-adminpc"
| where FileName endswith ".tar.gz"
| project Timestamp, FileName, FolderPath, InitiatingProcessCommandLine
| sort by Timestamp asc
```

## Flag 13:
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where FileName in~ ("robocopy.exe", "xcopy.exe", "cmd.exe")
| where ProcessCommandLine has_any ("Banking", "Financial", "Records")
| project Timestamp, FileName, ProcessCommandLine, AccountName
| sort by Timestamp asc
```

## Flag 14:
```kql
DeviceFileEvents
| where DeviceName == "azuki-adminpc"
| where FileName endswith ".tar.gz"
| where FolderPath has_any ("Crypto\\staging", "Windows\\Temp\\cache")
```

## Flag 15:
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where FileName in~ ("powershell.exe", "certutil.exe", "curl.exe", "bitsadmin.exe")
| where ProcessCommandLine has_any ("http", "https", "download", "wget", "iwr")
| project Timestamp, FileName, ProcessCommandLine, AccountName
| sort by Timestamp asc
```

## Flag 16:
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine contains "Login Data"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

## Flag 17:
```kql
DeviceNetworkEvents
| where DeviceName == "azuki-adminpc"
| where InitiatingProcessFileName =~ "curl.exe"
| where RemoteUrl contains "gofile.io"
| project Timestamp, RemoteIP, RemoteUrl, RemotePort
```

## Flag 18:
```kql
DeviceRegistryEvents
| where DeviceName == "azuki-fileserver01"
| where ActionType == "RegistryValueSet"
| where RegistryKey has "Run"
| where TimeGenerated > datetime(2025-11-22)
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
| sort by TimeGenerated asc
```

## Flag 19: 
```kql

```

## Flag 20: 
```kql
DeviceFileEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-25))
| where ActionType in~ ("FileDeleted", "FileModified")
| where FileName has "history" or FileName has "ConsoleHost"
| where FolderPath has_any ("AppData", "PowerShell", "PSReadLine")
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessAccountName
| sort by TimeGenerated desc
```

## Indicators of Compromise (IoCs)
### Network Indicators
- Attacker Source IP: [Refer to Flag 1 results]
- File Server IP: 10.1.0.188
- Exfiltration Destination: [Extract from Flag 16/17 command lines]

### File System Indicators
- Renamed Credential Tool: [Flag 14 - FileName and SHA256]
- Persistence Beacon: [Flag 19 - Registry Value Data path]
- Compressed Archives: [Flag 13 - Identify .7z/.zip file names]
- Staged Data Directory: [Flag 12 - robocopy destination path]

### Registry Indicators
- Persistence Key: HKCU/HKLM\Software\Microsoft\Windows\CurrentVersion\Run
- Persistence Value Name: [Flag 18 result]

### Process Execution
- mstsc.exe with specific command line parameters
- net.exe/net1.exe for share enumeration
- whoami.exe for privilege checking
- certutil.exe for file downloads
- 7z.exe for data compression
- curl.exe/powershell.exe for exfiltration
- Renamed executables targeting LSASS

## COMPROMISED ASSETS
### Confirmed Compromised Systems
-	azuki-sl (Initial Access Workstation)
-	Compromise Vector: Still investigating. We need to dig deeper into the logs to find exactly how they got in.
-	Attacker Control: Remote Desktop Access
-	Status: COMPROMISED
-	 </br>

-	azuki-fileserver01 (10.1.0.188)
-	Compromise Vector: They pivoted here from the workstation (azuki-sl) using RDP. 
-	Attacker Control: Fully compromised 
-	Status: CRITICALLY COMPROMISED 
#### Potentially Compromised Accounts
-	Any user account that logged into the file server (azuki-fileserver01) during the attack window should be considered compromised.
-	Service accounts usually have high privileges, so if they touched these infected machines, we have to assume the attackers have those keys now too.


File System Indicators
Renamed Credential Tool: [Flag 14 - FileName and SHA256]
Persistence Beacon: [Flag 19 - Registry Value Data path]
Compressed Archives: [Flag 13 - Identify .7z/.zip file names]
Staged Data Directory: [Flag 12 - robocopy destination path]

Registry Indicators
Persistence Key: HKCU/HKLM\Software\Microsoft\Windows\CurrentVersion\Run
Persistence Value Name: [Flag 18 result]

Process Execution
mstsc.exe with specific command line parameters
net.exe/net1.exe for share enumeration
whoami.exe for privilege checking
certutil.exe for file downloads
7z.exe for data compression
curl.exe/powershell.exe for exfiltration
Renamed executables targeting LSASS

## Technical Analysis
Affected Systems & Data:

- Target System: `azuki-adminpc` (CEO/Administrative Workstation).
- Compromised Accounts: `yuki.tanaka` (Primary Victim), `yuki.tanaka2` (Backdoor Account).

## Exfiltrated Data:
- Financial Records: Banking, QuickBooks, Tax, and Contract records.
- Credentials: Azuki-Passwords.kdbx (KeePass database), OLD-Passwords.txt (Plaintext), and Google Chrome Login Data.


