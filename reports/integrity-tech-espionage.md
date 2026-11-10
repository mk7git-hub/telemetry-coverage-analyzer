# Telemetry coverage: Integrity Tech espionage

Threat model: **15 techniques** (13 with ATT&CK detection guidance for the platforms in scope).

| Coverage | Techniques | Share |
| --- | --- | --- |
| Full (every signal an analytic needs is collected) | 3 | 23% |
| Partial (some signals missing) | 9 | 69% |
| None (blind spot) | 1 | 8% |
| No ATT&CK guidance for in-scope platforms | 2 | – |

Monthly ingest cost of the inventory: **$18,150**.

## Blind spots and partial coverage

| Technique | Name | Status | Missing signals |
| --- | --- | --- | --- |
| T1003.006 | DCSync | none | NSM:Content (Traffic on RPC DRSUAPI); WinEventLog:Security (EventCode=4662); WinEventLog:Security (EventCode=4929) |
| T1036.003 | Rename Legitimate Utilities | partial | EDR:AMSI (None) |
| T1059.001 | PowerShell | partial | WinEventLog:PowerShell (EventCode=400, 403); WinEventLog:Sysmon (EventCode=7) |
| T1059.006 | Python | partial | EDR:hunting (Advanced Hunting: DeviceProcessEvents + DeviceNetworkEvents) |
| T1059.007 | JavaScript | partial | WinEventLog:Sysmon (EventCode=7); m365:defender (ScriptBlockLogging + AMSI) |
| T1074.001 | Local Data Staging | partial | WinEventLog:Security (EventCode=4663, 4670, 4656) |
| T1114.002 | Remote Email Collection | partial | m365:purview (MailItemsAccessed & Exchange Audit) |
| T1133 | External Remote Services | partial | WinEventLog:Application (VPN, Citrix, or remote access gateway logs showing external IP addresses) |
| T1189 | Drive-by Compromise | partial | saas:auth (Refresh token issuance or refresh token usage from new IPs or user agents) |
| T1560.003 | Archive via Custom Method | partial | WinEventLog:Sysmon (EventCode=10) |

## Highest-value additions

Collecting these signals moves the most threat-model techniques toward full coverage:

| Log source | Channel / event | Data component | Techniques helped |
| --- | --- | --- | --- |
| WinEventLog:Sysmon | EventCode=7 | Module Load | 2: T1059.001, T1059.007 |
| WinEventLog:Security | EventCode=4662 | Active Directory Object Access | 1: T1003.006 |
| WinEventLog:Security | EventCode=4929 | Active Directory Object Deletion | 1: T1003.006 |
| NSM:Content | Traffic on RPC DRSUAPI | Network Traffic Content | 1: T1003.006 |
| EDR:AMSI | None | Command Execution | 1: T1036.003 |
| WinEventLog:PowerShell | EventCode=400, 403 | Process Metadata | 1: T1059.001 |
| EDR:hunting | Advanced Hunting: DeviceProcessEvents + DeviceNetworkEvents | Network Traffic Content | 1: T1059.006 |
| m365:defender | ScriptBlockLogging + AMSI | Script Execution | 1: T1059.007 |
| WinEventLog:Security | EventCode=4663, 4670, 4656 | File Access | 1: T1074.001 |
| m365:purview | MailItemsAccessed & Exchange Audit | Application Log Content | 1: T1114.002 |

## Cost versus value per source

| Source | Monthly cost | Techniques it enables | Only source for | Cost per technique | Normalized schema |
| --- | --- | --- | --- | --- | --- |
| WinEventLog:Security | $3,000 | 3 | 0 | $1,000.00 | yes |
| azure:signinlogs | $150 | 2 | 0 | $75.00 | yes |
| WinEventLog:Sysmon | $4,500 | 1 | 0 | $4,500.00 | yes |
| WinEventLog:PowerShell | $450 | 0 | 0 | – (no threat-model value) | no |
| AWS:CloudTrail | $600 | 0 | 0 | – (no threat-model value) | yes |
| m365:unified | $375 | 0 | 0 | – (no threat-model value) | no |
| saas:okta | $75 | 0 | 0 | – (no threat-model value) | yes |
| NSM:Firewall | $9,000 | 0 | 0 | – (no threat-model value) | no |

Sources with zero unique techniques and a high cost are candidates for filtering, sampling or a cheaper storage tier; sources that are the only coverage for several techniques are critical and need health monitoring.
