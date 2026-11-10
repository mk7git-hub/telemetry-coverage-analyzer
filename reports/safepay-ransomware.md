# Telemetry coverage: SafePay ransomware

Threat model: **29 techniques** (29 with ATT&CK detection guidance for the platforms in scope).

| Coverage | Techniques | Share |
| --- | --- | --- |
| Full (every signal an analytic needs is collected) | 12 | 41% |
| Partial (some signals missing) | 16 | 55% |
| None (blind spot) | 1 | 3% |
| No ATT&CK guidance for in-scope platforms | 0 | – |

Monthly ingest cost of the inventory: **$18,150**.

## Blind spots and partial coverage

| Technique | Name | Status | Missing signals |
| --- | --- | --- | --- |
| T1003.006 | DCSync | none | NSM:Content (Traffic on RPC DRSUAPI); WinEventLog:Security (EventCode=4662); WinEventLog:Security (EventCode=4929) |
| T1003.001 | LSASS Memory | partial | WinEventLog:Security (EventCode=4673); WinEventLog:Sysmon (EventCode=10) |
| T1021.001 | Remote Desktop Protocol | partial | WinEventLog:Security (EventCode=4778, EventCode=4779) |
| T1021.006 | Windows Remote Management | partial | NSM:Connections (Inbound on ports 5985/5986); WinEventLog:WinRM (EventCode=6) |
| T1027.002 | Software Packing | partial | WinEventLog:Sysmon (EventCode=10) |
| T1059.001 | PowerShell | partial | WinEventLog:PowerShell (EventCode=400, 403); WinEventLog:Sysmon (EventCode=7) |
| T1059.003 | Windows Command Shell | partial | EDR:scriptblock (Process Tree + Script Block Logging); WinEventLog:Sysmon (EventCode=7) |
| T1070.004 | File Deletion | partial | WinEventLog:Security (EventCode=4663, 4670, 4656); WinEventLog:Sysmon (EventCode=23) |
| T1133 | External Remote Services | partial | WinEventLog:Application (VPN, Citrix, or remote access gateway logs showing external IP addresses) |
| T1134.001 | Token Impersonation/Theft | partial | ETW:Token (api_call: DuplicateTokenEx, ImpersonateLoggedOnUser, SetThreadToken); WinEventLog:Sysmon (EventCode=10) |
| T1135 | Network Share Discovery | partial | WinEventLog:Sysmon (EventCode=17); etw:Microsoft-Windows-RPC (rpc_call: srvsvc.NetShareEnum / NetShareEnumAll from non-admin or unusual processes) |
| T1190 | Exploit Public-Facing Application | partial | ApplicationLog:IIS (IIS W3C logs in C:\inetpub\logs\LogFiles\W3SVC* (spikes in 5xx, RCE/SQLi/path traversal/JNDI patterns)); WinEventLog:Sysmon (EventCode=7) |
| T1218 | System Binary Proxy Execution | partial | WinEventLog:Sysmon (EventCode=7) |
| T1219 | Remote Access Tools | partial | WinEventLog:Sysmon (EventCode=12); WinEventLog:System (EventCode=7045) |
| T1548.002 | Bypass User Account Control | partial | WinEventLog:Sysmon (EventCode=10); WinEventLog:Sysmon (EventCode=7) |
| T1560.001 | Archive via Utility | partial | WinEventLog:Sysmon (EventCode=7) |
| T1567.002 | Exfiltration to Cloud Storage | partial | WinEventLog:Security (EventCode=4663, 4670, 4656) |

## Highest-value additions

Collecting these signals moves the most threat-model techniques toward full coverage:

| Log source | Channel / event | Data component | Techniques helped |
| --- | --- | --- | --- |
| WinEventLog:Sysmon | EventCode=7 | Module Load | 6: T1059.001, T1059.003, T1190, T1218, T1548.002, T1560.001 |
| WinEventLog:Sysmon | EventCode=10 | Process Access | 4: T1003.001, T1027.002, T1134.001, T1548.002 |
| WinEventLog:Security | EventCode=4663, 4670, 4656 | File Access | 2: T1070.004, T1567.002 |
| WinEventLog:Security | EventCode=4673 | User Account Metadata | 1: T1003.001 |
| WinEventLog:Security | EventCode=4662 | Active Directory Object Access | 1: T1003.006 |
| WinEventLog:Security | EventCode=4929 | Active Directory Object Deletion | 1: T1003.006 |
| NSM:Content | Traffic on RPC DRSUAPI | Network Traffic Content | 1: T1003.006 |
| WinEventLog:Security | EventCode=4778, EventCode=4779 | Logon Session Metadata | 1: T1021.001 |
| WinEventLog:WinRM | EventCode=6 | Service Metadata | 1: T1021.006 |
| NSM:Connections | Inbound on ports 5985/5986 | Network Traffic Flow | 1: T1021.006 |

## Cost versus value per source

| Source | Monthly cost | Techniques it enables | Only source for | Cost per technique | Normalized schema |
| --- | --- | --- | --- | --- | --- |
| AWS:CloudTrail | $600 | 4 | 3 | $150.00 | yes |
| WinEventLog:Sysmon | $4,500 | 7 | 1 | $642.86 | yes |
| WinEventLog:Security | $3,000 | 7 | 0 | $428.57 | yes |
| m365:unified | $375 | 2 | 0 | $187.50 | no |
| azure:signinlogs | $150 | 1 | 0 | $150.00 | yes |
| saas:okta | $75 | 1 | 0 | $75.00 | yes |
| WinEventLog:PowerShell | $450 | 0 | 0 | – (no threat-model value) | no |
| NSM:Firewall | $9,000 | 0 | 0 | – (no threat-model value) | no |

Sources with zero unique techniques and a high cost are candidates for filtering, sampling or a cheaper storage tier; sources that are the only coverage for several techniques are critical and need health monitoring.
