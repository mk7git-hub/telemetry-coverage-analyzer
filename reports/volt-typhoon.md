# Telemetry coverage: Volt Typhoon

Threat model: **81 techniques** (62 with ATT&CK detection guidance for the platforms in scope).

| Coverage | Techniques | Share |
| --- | --- | --- |
| Full (every signal an analytic needs is collected) | 24 | 39% |
| Partial (some signals missing) | 38 | 61% |
| None (blind spot) | 0 | 0% |
| No ATT&CK guidance for in-scope platforms | 19 | – |

Monthly ingest cost of the inventory: **$18,150**.

## Blind spots and partial coverage

| Technique | Name | Status | Missing signals |
| --- | --- | --- | --- |
| T1003.001 | LSASS Memory | partial | WinEventLog:Security (EventCode=4673); WinEventLog:Sysmon (EventCode=10) |
| T1003.003 | NTDS | partial | WinEventLog:Microsoft-Windows-VSS (Volume Shadow Copy Creation); WinEventLog:Sysmon (EventCode=2) |
| T1006 | Direct Volume Access | partial | WinEventLog:Sysmon (EventCode=10) |
| T1010 | Application Window Discovery | partial | WinEventLog:Sysmon (EventCode=10) |
| T1016.001 | Internet Connection Discovery | partial | WinEventLog:Security (EventCode=5156, 5157) |
| T1021.001 | Remote Desktop Protocol | partial | WinEventLog:Security (EventCode=4778, EventCode=4779) |
| T1027.002 | Software Packing | partial | WinEventLog:Sysmon (EventCode=10) |
| T1047 | Windows Management Instrumentation | partial | WinEventLog:WMI (EventCode=5857, 5858, 5860, 5861) |
| T1056.001 | Keylogging | partial | WinEventLog:Security (EventCode=4663, 4670, 4656); WinEventLog:Sysmon (EventCode=10); WinEventLog:System (EventCode=7045) |
| T1057 | Process Discovery | partial | WinEventLog:Sysmon (EventCode=10) |
| T1059.001 | PowerShell | partial | WinEventLog:PowerShell (EventCode=400, 403); WinEventLog:Sysmon (EventCode=7) |
| T1059.003 | Windows Command Shell | partial | EDR:scriptblock (Process Tree + Script Block Logging); WinEventLog:Sysmon (EventCode=7) |
| T1068 | Exploitation for Privilege Escalation | partial | WinEventLog:Sysmon (EventCode=6) |
| T1070.004 | File Deletion | partial | WinEventLog:Security (EventCode=4663, 4670, 4656); WinEventLog:Sysmon (EventCode=23) |
| T1070.007 | Clear Network Connection History and Configurations | partial | EDR:cli (Command Line Telemetry); WinEventLog:Security (EventCode=4663, 4670, 4656); WinEventLog:Security (Firewall Rule Modification) |
| T1074 | Data Staged | partial | WinEventLog:Security (EventCode=4663, 4670, 4656) |
| T1074.001 | Local Data Staging | partial | WinEventLog:Security (EventCode=4663, 4670, 4656) |
| T1087.002 | Domain Account | partial | NSM:Flow (LDAP Bind/Search) |
| T1090 | Proxy | partial | NSM:Connections (Outbound Connection) |
| T1090.001 | Internal Proxy | partial | Windows Firewall Log (SMB over high port) |
| T1090.003 | Multi-hop Proxy | partial | dns:query (Outbound resolution to hidden service domains (e.g., `.onion`)) |
| T1113 | Screen Capture | partial | WinEventLog:Sysmon (EventCode=7) |
| T1120 | Peripheral Device Discovery | partial | WinEventLog:Sysmon (EventCode=10) |
| T1124 | System Time Discovery | partial | EDR:Telemetry (Process lineage and API usage enrichment (GetSystemTime, GetTimeZoneInformation, NtQuerySystemTime)); WinEventLog:Sysmon (EventCode=10); WinEventLog:Sysmon (EventCode=7); WinEventLog:TaskScheduler (EventCo |
| T1133 | External Remote Services | partial | WinEventLog:Application (VPN, Citrix, or remote access gateway logs showing external IP addresses) |
| T1140 | Deobfuscate/Decode Files or Information | partial | WinEventLog:Sysmon (EventCode=10) |
| T1190 | Exploit Public-Facing Application | partial | ApplicationLog:IIS (IIS W3C logs in C:\inetpub\logs\LogFiles\W3SVC* (spikes in 5xx, RCE/SQLi/path traversal/JNDI patterns)); WinEventLog:Sysmon (EventCode=7) |
| T1218 | System Binary Proxy Execution | partial | WinEventLog:Sysmon (EventCode=7) |
| T1497.001 | System Checks | partial | WinEventLog:Sysmon (EventCode=10); WinEventLog:Sysmon (EventCode=7) |
| T1505.003 | Web Shell | partial | NSM:Flow (Inbound HTTP POST with suspicious payload size or user-agent) |
| T1552.004 | Private Keys | partial | WinEventLog:Security (EventCode=5145) |
| T1555.003 | Credentials from Web Browsers | partial | WinEventLog:Security (EventCode=4663, 4670, 4656); WinEventLog:Sysmon (EventCode=10) |
| T1560.001 | Archive via Utility | partial | WinEventLog:Sysmon (EventCode=7) |
| T1570 | Lateral Tool Transfer | partial | WinEventLog:Security (EventCode=5140) |
| T1573.001 | Symmetric Cryptography | partial | WinEventLog:Sysmon (EventCode=7) |
| T1614 | System Location Discovery | partial | etw:Microsoft-Windows-Kernel-Base (GetLocaleInfoW, GetTimeZoneInformation API calls) |
| T1654 | Log Enumeration | partial | WinEventLog:Security (EventCode=4663, 4670, 4656) |
| T1685.005 | Clear Windows Event Logs | partial | WinEventLog:Security (EventCode=1102); WinEventLog:Sysmon (EventCode=23) |

## Highest-value additions

Collecting these signals moves the most threat-model techniques toward full coverage:

| Log source | Channel / event | Data component | Techniques helped |
| --- | --- | --- | --- |
| WinEventLog:Sysmon | EventCode=10 | Process Access | 11: T1003.001, T1006, T1010, T1027.002, T1056.001, T1057… |
| WinEventLog:Sysmon | EventCode=7 | Module Load | 9: T1059.001, T1059.003, T1113, T1124, T1190, T1218… |
| WinEventLog:Security | EventCode=4663, 4670, 4656 | File Access | 6: T1056.001, T1070.004, T1074, T1074.001, T1555.003, T1654 |
| WinEventLog:Sysmon | EventCode=23 | File Deletion | 2: T1070.004, T1685.005 |
| WinEventLog:Security | EventCode=4673 | User Account Metadata | 1: T1003.001 |
| WinEventLog:Sysmon | EventCode=2 | File Modification | 1: T1003.003 |
| WinEventLog:Microsoft-Windows-VSS | Volume Shadow Copy Creation | Volume Creation | 1: T1003.003 |
| WinEventLog:Security | EventCode=5156, 5157 | Network Connection Creation | 1: T1016.001 |
| WinEventLog:Security | EventCode=4778, EventCode=4779 | Logon Session Metadata | 1: T1021.001 |
| WinEventLog:WMI | EventCode=5857, 5858, 5860, 5861 | WMI Creation | 1: T1047 |

## Cost versus value per source

| Source | Monthly cost | Techniques it enables | Only source for | Cost per technique | Normalized schema |
| --- | --- | --- | --- | --- | --- |
| WinEventLog:Sysmon | $4,500 | 18 | 7 | $250.00 | yes |
| AWS:CloudTrail | $600 | 3 | 2 | $200.00 | yes |
| WinEventLog:Security | $3,000 | 10 | 1 | $300.00 | yes |
| WinEventLog:PowerShell | $450 | 8 | 0 | $56.25 | no |
| azure:signinlogs | $150 | 1 | 0 | $150.00 | yes |
| saas:okta | $75 | 1 | 0 | $75.00 | yes |
| m365:unified | $375 | 0 | 0 | – (no threat-model value) | no |
| NSM:Firewall | $9,000 | 0 | 0 | – (no threat-model value) | no |

Sources with zero unique techniques and a high cost are candidates for filtering, sampling or a cheaper storage tier; sources that are the only coverage for several techniques are critical and need health monitoring.
