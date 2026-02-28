# Compliance & Framework Mapping

This document maps SOC Lab Docker's detection capabilities to two widely used security frameworks: **CIS Controls v8** and the **NIST Cybersecurity Framework (CSF) 2.0**.

These mappings serve two purposes:
1. Show how the lab's detections align with enterprise security control requirements
2. Help detection engineers understand the *business context* behind each query — why it matters, not just what it catches

---

## CIS Controls v8

The [CIS Controls](https://www.cisecurity.org/controls/v8) are a prioritized set of safeguards for cyber defense. Version 8 reorganized the controls around activities (not asset types), making them more technology-agnostic.

### Control Coverage Overview

| CIS Control | Title | Lab Coverage |
|---|---|---|
| CIS 8 | Audit Log Management | Core — entire lab |
| CIS 5 | Account Management | Authentication detections |
| CIS 10 | Malware Defenses | Process-based detections |
| CIS 12 | Network Infrastructure Management | Network detections |
| CIS 13 | Network Monitoring and Defense | Exfiltration, C2 detections |
| CIS 16 | Application Software Security | Lateral movement detections |
| CIS 17 | Incident Response Management | Alerting framework, playbooks |

### Detection-Level Mapping

| Detection | CIS Control | Safeguard | Notes |
|---|---|---|---|
| Brute Force SSH | CIS 5.2 | Use Unique Passwords | Detects password-guessing against accounts |
| Brute Force SSH | CIS 8.11 | Conduct Audit Log Reviews | Aggregated authentication failure analysis |
| Account Lockout Spike | CIS 5.2 | Use Unique Passwords | Password spray pattern across multiple accounts |
| Account Lockout Spike | CIS 8.11 | Conduct Audit Log Reviews | Time-windowed failure aggregation |
| RDP Lateral Movement | CIS 12.8 | Manage Infrastructure Network Connections | Unusual RDP connections to internal hosts |
| RDP Lateral Movement | CIS 13.8 | Deploy a Network Intrusion Detection Solution | Network-layer lateral movement signal |
| PsExec Detection | CIS 10.1 | Deploy and Maintain Anti-Malware Software | PSEXESVC.exe presence indicates remote execution tool |
| PsExec Detection | CIS 16.10 | Apply Secure Design Principles | Admin tool misuse for remote code execution |
| WMI Execution | CIS 10.1 | Deploy and Maintain Anti-Malware Software | WmiPrvSE.exe spawning interactive shells |
| WMI Execution | CIS 8.8 | Collect Command-Line Audit Logs | WMI child process command line analysis |
| Local Privilege Escalation | CIS 5.4 | Restrict Administrator Privileges to Dedicated Administrator Accounts | SYSTEM-integrity process from non-system parents |
| Local Privilege Escalation | CIS 8.8 | Collect Command-Line Audit Logs | Process integrity level monitoring |
| Scheduled Task Creation | CIS 4.1 | Establish and Maintain a Secure Configuration Process | Unauthorized persistence mechanism creation |
| Scheduled Task Creation | CIS 8.8 | Collect Command-Line Audit Logs | schtasks.exe invocation monitoring |
| Large Data Transfer | CIS 13.1 | Centralize Security Event Alerting | Outbound connection anomaly detection |
| Large Data Transfer | CIS 13.9 | Deploy Port-Level Access Control | Non-standard outbound port monitoring |

### Lab Platform Alignment

| CIS Control | Safeguard | How the Lab Addresses It |
|---|---|---|
| CIS 8.1 | Establish and Maintain an Audit Log Management Process | Lab stack (Elasticsearch + Filebeat) provides centralized log collection and retention |
| CIS 8.2 | Collect Audit Logs | Mock generator produces ECS-aligned events for authentication, process, and network categories |
| CIS 8.5 | Collect Detailed Audit Logs | Process command-line logging (`process.command_line`) captured for all process events |
| CIS 8.9 | Centralize Audit Logs | Single Elasticsearch instance consolidates all event streams |
| CIS 8.11 | Conduct Audit Log Reviews | Detection queries implement the review logic; dashboards provide continuous visibility |

---

## NIST Cybersecurity Framework 2.0

The [NIST CSF](https://www.nist.gov/cyberframework) organizes cybersecurity activities into six core functions: **Govern, Identify, Protect, Detect, Respond, Recover**. SOC Lab Docker's capabilities primarily address the **Detect** and **Respond** functions.

### Function Coverage

| CSF Function | Lab Coverage |
|---|---|
| Govern (GV) | Documented policies in BEST_PRACTICES.md and detection methodology |
| Identify (ID) | Asset inventory implied via host.name and event tracking |
| Protect (PR) | Not the lab's focus — this is a detection/response tool |
| Detect (DE) | Core focus — all detection queries, dashboards, Sigma rules |
| Respond (RS) | Alerting framework, SOAR playbooks, response playbooks in ALERTING.md |
| Recover (RC) | Out of scope for this lab |

### Detection-Level Mapping

| Detection | NIST CSF Category | Subcategory | Notes |
|---|---|---|---|
| Brute Force SSH | DE.CM | DE.CM-01 | Network and network services are monitored for anomalies |
| Brute Force SSH | DE.AE | DE.AE-02 | Potentially adverse events are analyzed |
| Account Lockout Spike | DE.CM | DE.CM-03 | Personnel activity is monitored |
| Account Lockout Spike | DE.AE | DE.AE-06 | Event data are collected and correlated |
| RDP Lateral Movement | DE.CM | DE.CM-01 | Network connections monitored for unauthorized access |
| RDP Lateral Movement | DE.AE | DE.AE-07 | Cyber threat intelligence is integrated into analysis |
| PsExec Detection | DE.CM | DE.CM-09 | Computing hardware and software are monitored |
| PsExec Detection | RS.AN | RS.AN-03 | Analysis is performed to establish what has occurred |
| WMI Execution | DE.CM | DE.CM-09 | Computing hardware and software are monitored |
| WMI Execution | DE.AE | DE.AE-02 | Potentially adverse events are analyzed |
| Local Privilege Escalation | DE.CM | DE.CM-09 | Computing hardware and software are monitored |
| Local Privilege Escalation | DE.AE | DE.AE-04 | The estimated impact and scope of adverse events are understood |
| Scheduled Task Creation | DE.CM | DE.CM-09 | Computing hardware and software are monitored |
| Scheduled Task Creation | PR.PS | PR.PS-04 | Log records are generated and made available |
| Large Data Transfer | DE.CM | DE.CM-01 | Network is monitored to detect potential events |
| Large Data Transfer | DE.AE | DE.AE-06 | Event data are collected and correlated from multiple sources |

### Platform-Level Alignment

| CSF Subcategory | Description | How the Lab Addresses It |
|---|---|---|
| DE.CM-01 | Networks and network services are monitored | Network event collection and detection queries covering lateral movement and exfiltration |
| DE.CM-03 | Personnel activity and technology usage are monitored | Authentication and process event monitoring with user context |
| DE.CM-09 | Computing hardware and software activities are monitored | Process-level event collection including command lines, integrity levels, and parent-child relationships |
| DE.AE-02 | Potentially adverse events are analyzed | All detection queries implement threshold-based analysis with enrichment |
| DE.AE-04 | The estimated impact and scope of adverse events are understood | Entity mapping and aggregation in queries surfaces affected users, hosts, and IPs |
| DE.AE-06 | Event data are collected and correlated from multiple sources | Multi-event correlation via EQL sequences and ES|QL aggregations |
| RS.AN-03 | Analysis is performed to establish what has occurred during an incident | Response playbooks in ALERTING.md provide post-detection investigation steps |
| RS.CO-02 | Incidents are reported consistent with established criteria | Alerting framework with configurable severity thresholds and notification backends |
| RS.MA-04 | Incidents are contained | SOAR playbooks (host isolation, ticket creation) automate initial containment actions |

---

## MITRE ATT&CK Coverage Summary

For reference, the techniques covered across all lab detections:

| Tactic | Technique | Detection |
|---|---|---|
| Credential Access | T1110 – Brute Force | Brute Force SSH, Account Lockout Spike |
| Credential Access | T1110.001 – Password Guessing | Brute Force SSH |
| Credential Access | T1110.003 – Password Spraying | Account Lockout Spike |
| Lateral Movement | T1021.001 – RDP | RDP Lateral Movement |
| Lateral Movement | T1021.002 – SMB/Admin Shares | PsExec Detection |
| Lateral Movement | T1047 – WMI | WMI Execution |
| Privilege Escalation | T1068 – Exploitation for Privilege Escalation | Local Privilege Escalation |
| Privilege Escalation | T1134 – Access Token Manipulation | Local Privilege Escalation |
| Persistence | T1053.005 – Scheduled Task | Scheduled Task Creation |
| Exfiltration | T1041 – Exfiltration Over C2 Channel | Large Data Transfer |
| Exfiltration | T1048 – Exfiltration Over Alternative Protocol | Large Data Transfer |

---

## Using These Mappings

**For detection gap analysis:** Use the tables above to identify which CIS safeguards or NIST subcategories have no lab coverage, then prioritize new detections accordingly.

**For reporting and communication:** When explaining detection work to non-technical stakeholders, frame findings in terms of CIS Controls or NIST CSF categories. "We detected a violation of CIS 5.2" communicates more clearly than "we saw too many failed authentications from one IP."

**For certification preparation:** CIS Controls v8 and NIST CSF 2.0 are referenced by SOC 2, ISO 27001, and most enterprise security programs. Understanding where your detection coverage maps to these frameworks is a practical skill for detection engineers working in compliance-adjacent roles.
