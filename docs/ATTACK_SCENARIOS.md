# Attack Scenarios Reference

Documentation for the SOC Lab Docker attack simulation scripts. Each scenario describes the event chain generated, the detection opportunities it creates, its MITRE ATT&CK mapping, and known gaps (blind spots) where defenders would need additional data sources or tuning.

---

## Table of Contents

1. [C2 Beacon Simulation](#1-c2-beacon-simulation)
2. [Persistence Mechanism Simulation](#2-persistence-mechanism-simulation)
3. [Privilege Escalation Simulation](#3-privilege-escalation-simulation)
4. [APT Multi-Step Scenario](#4-apt-multi-step-scenario)
5. [Cross-Scenario Notes](#5-cross-scenario-notes)

---

## 1. C2 Beacon Simulation

**Script:** `scripts/c2_beacon_simulation.sh`

### What It Simulates

A host is compromised via a spearphishing email with a malicious Office document. The macro executes a PowerShell download cradle that fetches and runs a lightweight implant from a non-standard location. The implant checks in with a C2 server and sends periodic heartbeat connections at a regular interval. The attacker issues a command via the C2 channel; the implant spawns cmd.exe and returns output to the server.

### Event Chain

| Step | Description | Key Field(s) |
|------|-------------|--------------|
| 1 | `winword.exe` spawns `cmd.exe` (macro executed) | `process.parent.name: winword.exe`, `process.name: cmd.exe` |
| 2 | `cmd.exe` spawns `powershell.exe` with encoded command | `process.command_line` contains `-EncodedCommand` |
| 3 | DNS query for C2 domain before download | `dns.question.name`, `dns.resolved_ip` |
| 4 | PowerShell downloads implant from C2 (65KB) | `network.bytes: 65536`, `destination.ip: <C2_IP>` |
| 5 | Implant binary executed from `C:\ProgramData\` | `process.executable` path outside System32/Program Files |
| 6 | DNS re-resolution; initial 512-byte check-in | Regular small `network.bytes` to same IP |
| 7 | Repeated heartbeat connections at fixed interval | Multiple identical connections, uniform bytes, fixed dest |
| 8 | C2 issues task; implant spawns `cmd.exe` | `process.parent.name: svchost32.exe` (or implant name) |
| 9 | Discovery commands run via tasked shell | `process.name` in (whoami.exe, net.exe, ipconfig.exe) |
| 10 | Command output returned to C2 (8KB) | Larger single outbound `network.bytes` between beacons |

### MITRE ATT&CK

| Technique | ID | Phase |
|---|---|---|
| Phishing: Spearphishing Attachment | T1566.001 | Initial Access |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Execution |
| Application Layer Protocol: Web Protocols | T1071.001 | Command & Control |
| Scheduled Transfer | T1029 | Command & Control |
| Exfiltration Over C2 Channel | T1041 | Exfiltration |
| Data Encoding: Standard Encoding | T1132.001 | Command & Control |

### Detection Opportunities

- **Suspicious process lineage:** `winword.exe → cmd.exe → powershell.exe` is abnormal. Office applications should never spawn cmd.exe or PowerShell directly. Alert on any Office process spawning a shell.
- **Encoded PowerShell:** `-EncodedCommand` or `-enc` flags on `powershell.exe` with no obvious benign explanation. High-fidelity when combined with `-WindowStyle Hidden` or `-ExecutionPolicy Bypass`.
- **Executable in non-standard path:** Process launched from `C:\ProgramData\`, `C:\Users\*\AppData\`, or temp directories. Especially suspicious if the parent is PowerShell.
- **Beaconing pattern:** Statistical analysis of connection frequency to a single external IP. Key indicators: regular interval (±10%), consistent small packet size, low jitter, non-browser process.
- **Non-browser HTTPS:** A process like `svchost32.exe` making TLS/443 connections. Browser processes (chrome.exe, firefox.exe, msedge.exe) are expected on 443; arbitrary executables are not.

### Blind Spots

- **Encrypted C2 traffic:** Without TLS inspection, beacon contents are opaque. Network metadata (interval, size, destination) is the only signal.
- **Domain fronting:** If the C2 uses a CDN (Cloudflare, Azure Front Door), the DNS destination looks legitimate. Requires certificate inspection or threat intel on the actual C2 IP.
- **Living-off-the-land:** If the implant uses built-in Windows binaries (e.g., `certutil`, `regsvr32`) instead of a custom executable, process-path detections will not fire.
- **Low-and-slow beaconing:** Intervals of 6–24 hours produce very few events, making statistical analysis ineffective without long retention windows.

### How to Run

```bash
bash scripts/c2_beacon_simulation.sh

# Customise:
BEACON_COUNT=10 BEACON_INTERVAL_MS=1000 bash scripts/c2_beacon_simulation.sh
C2_IP=198.51.100.42 C2_PORT=8080 bash scripts/c2_beacon_simulation.sh
```

---

## 2. Persistence Mechanism Simulation

**Script:** `scripts/persistence_simulation.sh`

### What It Simulates

An attacker with an established foothold on a host installs multiple overlapping persistence mechanisms to ensure they survive reboots, user logoffs, and AV/EDR cleanup attempts. The scenario demonstrates the belt-and-suspenders approach common in real intrusions: if one persistence mechanism is discovered and removed, the others continue to provide access.

### Event Chain

| Step | Description | Key Field(s) |
|------|-------------|--------------|
| 1a | `reg.exe` adds HKCU Run key pointing to payload | `registry.path` contains `CurrentVersion\Run` |
| 1b | `reg.exe` adds HKLM Run key (requires admin) | `registry.key: HKLM\...`, `user.name: SYSTEM` |
| 2a | `schtasks.exe /create` – ONLOGON trigger, HIGHEST privilege | `task.trigger: ONLOGON`, `task.run_level: HIGHEST` |
| 2b | `schtasks.exe /create` – ONSTART trigger, SYSTEM context | `task.trigger: ONSTART`, `user.name: SYSTEM` |
| 3a | `mofcomp.exe` compiles malicious MOF file | `process.name: mofcomp.exe` with non-system path argument |
| 3b | WMI filter, consumer, and binding created | `event.action: wmi_subscription_created` |
| 4a | `sc.exe create` installs service with non-System32 binary | `service.binary_path` outside System32 |
| 4b | Service started (`services.exe` spawns implant) | `process.parent.name: services.exe` |
| 5a | PowerShell creates LNK shortcut in Startup folder | `process.command_line` contains `WScript.Shell` + `.lnk` |
| 5b | LNK file created in `\AppData\Roaming\...\Startup\` | `file.directory` matches Startup path |

### MITRE ATT&CK

| Technique | ID | Phase |
|---|---|---|
| Boot or Logon Autostart: Registry Run Keys | T1547.001 | Persistence |
| Scheduled Task/Job: Scheduled Task | T1053.005 | Persistence / Privilege Escalation |
| Event Triggered Execution: WMI Event Subscription | T1546.003 | Persistence |
| Create or Modify System Process: Windows Service | T1543.003 | Persistence / Privilege Escalation |
| Boot or Logon Autostart: Startup Folder | T1547.001 | Persistence |

### Detection Opportunities

- **Registry Run key writes:** Alert on any write to `HKCU\...\CurrentVersion\Run` or `HKLM\...\CurrentVersion\Run` by a non-installer process (i.e., not `msiexec.exe`, not a signed software updater).
- **Scheduled task in OS-looking path:** Tasks created under `\Microsoft\Windows\UpdateOrchestrator\` or similar paths by non-SYSTEM processes. Legit OS tasks are rarely created interactively.
- **WMI subscription trinity:** A WMI `__EventFilter`, `CommandLineEventConsumer`, and `__FilterToConsumerBinding` created in sequence within a short window is a near-certain indicator of malicious persistence.
- **Service with non-System32 binary:** `sc.exe create` with a `binPath` pointing outside `%SystemRoot%\System32\` or `%ProgramFiles%` is suspicious. Most legitimate services use vetted install paths.
- **LNK file in Startup directory by unexpected parent:** `powershell.exe` or `cmd.exe` writing a `.lnk` file to a Startup folder path. Legitimate shortcut creation happens via installers, not shells.

### Blind Spots

- **COM hijacking:** Persistence via COM object redirection (`HKCU\Software\Classes\CLSID\`) does not produce process or registry events that look unusual in isolation.
- **DLL sideloading:** Placing a malicious DLL next to a legitimate binary generates no persistence-specific events — only process events when the DLL is loaded.
- **Image File Execution Options (IFEO):** Debugger hijacking via `HKLM\...\Image File Execution Options\` is a persistence/privilege technique not covered in this simulation.
- **BITS jobs:** Background Intelligent Transfer Service jobs for persistence generate no standard process or registry events.

### How to Run

```bash
bash scripts/persistence_simulation.sh

# Customise:
TARGET_HOST=workstation-15 TARGET_USER=bsmith bash scripts/persistence_simulation.sh
PAYLOAD_PATH="C:\\Temp\\update.exe" bash scripts/persistence_simulation.sh
```

---

## 3. Privilege Escalation Simulation

**Script:** `scripts/privilege_escalation_simulation.sh`

### What It Simulates

An attacker with a standard domain user account escalates privileges in two directions: horizontally (Kerberoasting a service account for offline cracking to gain access to its privileges) and vertically (bypassing UAC to get a High-integrity shell, then stealing a SYSTEM token via token impersonation). The scenario ends with the attacker adding their account to Domain Admins.

### Event Chain

| Step | Description | Key Field(s) |
|------|-------------|--------------|
| 1 | `whoami /all`, `whoami /priv`, `net localgroup administrators` | `process.name: whoami.exe`, `process.command_line` contains `/priv` |
| 2 | `setspn.exe -T CORP -Q */*` – SPN enumeration | `process.name: setspn.exe` |
| 3 | PowerShell LDAP query for service accounts with SPNs | LDAP traffic to DC port 389 |
| 4 | Kerberos TGS request for `svc_mssql` with RC4 encryption | `authentication.ticket.encryption_type: RC4-HMAC`, port 88 |
| 5a | `reg.exe` writes to `HKCU\...\ms-settings\shell\open\command` | `registry.path` contains `ms-settings` |
| 5b | `DelegateExecute` value set (required for UAC bypass trigger) | `registry.value.name: DelegateExecute` |
| 6 | `fodhelper.exe` launched by attacker | `process.name: fodhelper.exe` |
| 7 | `cmd.exe` spawned by `fodhelper.exe` with High integrity | `process.integrity_level: High`, `process.parent.name: fodhelper.exe` |
| 8 | Token impersonation — `cmd.exe` running as SYSTEM | `process.integrity_level: System` under High parent |
| 9 | `net group "Domain Admins" <user> /add /domain` | `process.command_line` contains `Domain Admins` + `/add` |
| 10 | Auth success for user on DC (now Domain Admin) | `event.action: logon`, `event.outcome: success`, Kerberos |

### MITRE ATT&CK

| Technique | ID | Phase |
|---|---|---|
| Permission Groups Discovery: Local Groups | T1069.001 | Discovery |
| Permission Groups Discovery: Domain Groups | T1069.002 | Discovery |
| Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | Credential Access |
| Bypass User Account Control: fodhelper | T1548.002 | Privilege Escalation / Defense Evasion |
| Access Token Manipulation: Token Impersonation | T1134.001 | Privilege Escalation / Defense Evasion |
| Valid Accounts: Domain Accounts | T1078.002 | Defense Evasion / Persistence |

### Detection Opportunities

- **Kerberoasting:** RC4-encrypted (`0x17`) TGS requests for service account SPNs from a workstation (not a server). In modern environments, service accounts should use AES encryption. Any RC4 TGS request to a service SPN is high-fidelity on AES-enforced domains.
- **SPN enumeration:** `setspn.exe` executed interactively by a non-admin user, or large LDAP queries from a workstation to a DC on port 389 with SPN-related filters.
- **ms-settings registry key:** Creation of `HKCU\Software\Classes\ms-settings\shell\open\command` is a strong indicator of the fodhelper UAC bypass. This key has no legitimate use.
- **fodhelper spawning child processes:** `fodhelper.exe` (a Windows built-in) spawning anything other than itself is anomalous. Alert on any child process of `fodhelper.exe`.
- **Process integrity level escalation:** A process running at High or System integrity under a parent at Medium integrity. Especially suspicious if the parent is a UAC bypass binary.
- **Domain Admins group modification:** Any interactive modification of privileged groups via `net.exe` should alert immediately.

### Blind Spots

- **Offline Kerberoasting:** The RC4 ticket is cracked offline — only the ticket request event is visible in logs, not the cracking activity.
- **AES Kerberoasting:** If the environment uses AES-only, Kerberoasting still works but the RC4-specific detection rule won't fire. AES-based Kerberoasting is harder to detect purely from ticket type.
- **Token theft via process injection:** More sophisticated token theft (e.g., via `NtImpersonateThread`) does not produce the high-level event shown in the simulation; requires EDR with kernel hooks.
- **UAC bypass variants:** There are dozens of UAC bypass techniques (DelegateExecute, CMSTPLUA, ICMLuaUtil, etc.). Detection rules tuned to fodhelper will miss others.

### How to Run

```bash
bash scripts/privilege_escalation_simulation.sh

# Customise:
TARGET_USER=rjones SVC_ACCOUNT=svc_exchange bash scripts/privilege_escalation_simulation.sh
DOMAIN=ACME DC_HOST=addc-01 bash scripts/privilege_escalation_simulation.sh
```

---

## 4. APT Multi-Step Scenario

**Script:** `scripts/apt_scenario.sh`

### What It Simulates

A complete intrusion lifecycle modeled on documented nation-state TTPs (loosely based on APT29/Cozy Bear and similar groups). All seven phases use the same victim host, user, and attacker infrastructure so events are correlated as a single campaign. This is the most realistic scenario in the lab — running it generates enough events to practice building a full incident timeline.

### Event Chain (Full Kill Chain)

#### Phase 1 – Initial Access (T1566.001)

| Step | Event |
|------|-------|
| 1 | `outlook.exe` opens `WINWORD.EXE` with a `.docm` attachment |
| 2 | `winword.exe` spawns `cmd.exe` (macro executes) |
| 3 | `cmd.exe` spawns `powershell.exe` with encoded command |

#### Phase 2 – Execution & C2 (T1059.001, T1071.001)

| Step | Event |
|------|-------|
| 4 | PowerShell executes encoded download cradle |
| 5 | DNS query resolves C2 domain |
| 6 | 96KB download from C2 (implant payload) |
| 7 | Implant (`wmisvc32.exe`) executes from `C:\ProgramData\WMI\` |
| 8 | Initial 512-byte C2 check-in |

#### Phase 3 – Persistence (T1053.005, T1547.001)

| Step | Event |
|------|-------|
| 9 | `schtasks.exe /create` (ONLOGON, HIGHEST privilege) |
| 10 | `scheduled_task_created` event |
| 11 | `reg.exe add HKCU\...\Run AUMonitor` |
| 12 | Registry `value_set` event |

#### Phase 4 – Discovery (T1082, T1069, T1016)

| Step | Event |
|------|-------|
| 13–22 | 10 recon commands: `systeminfo`, `ipconfig /all`, `arp -a`, `net user /domain`, `net group "Domain Admins" /domain`, `net group "Enterprise Admins" /domain`, `nltest /dclist`, `nslookup`, `tasklist /v`, `netstat -ano` |
| 23 | LDAP query to DC (port 389) for user enumeration |

#### Phase 5 – Credential Access (T1558.003)

| Step | Event |
|------|-------|
| 24 | PowerShell SPN enumeration (Get-ADUser) |
| 25 | LDAP network event to DC |
| 26 | Kerberos TGS request for `svc_backup` (RC4-HMAC, port 88) |
| 27 | Network event to DC port 88 |

#### Phase 6 – Lateral Movement (T1021.002)

| Step | Event |
|------|-------|
| 28 | Auth success for `svc_backup` on DC (cracked credential) |
| 29 | SMB connection to DC port 445 |
| 30 | `net.exe use \\dc-01\ADMIN$` |
| 31 | `psexec.exe` executed |
| 32 | PSEXESVC service created on DC |
| 33 | `cmd.exe` spawned on DC (SYSTEM integrity) |
| 34–36 | DC-side recon: `ntdsutil`, `vssadmin list shadows`, `wmic shadowcopy call create` |

#### Phase 7 – Exfiltration (T1560.001, T1048.003)

| Step | Event |
|------|-------|
| 37–38 | `7z.exe` archives `ntds.dit` + SYSTEM hive |
| 39 | `certutil.exe -encode` (base64 encoding) |
| 40 | 100MB network transfer to exfil server (port 8443) |
| 41 | Second 50MB burst (split transfer) |
| 42–46 | Cleanup: 3x `wevtutil.exe cl`, 2x `del` |

### MITRE ATT&CK (Full Chain)

| Technique | ID | Phase |
|---|---|---|
| Phishing: Spearphishing Attachment | T1566.001 | Initial Access |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Execution |
| Application Layer Protocol: Web Protocols | T1071.001 | Command & Control |
| Scheduled Task/Job: Scheduled Task | T1053.005 | Persistence |
| Boot or Logon Autostart: Registry Run Keys | T1547.001 | Persistence |
| System Information Discovery | T1082 | Discovery |
| Permission Groups Discovery: Domain Groups | T1069.002 | Discovery |
| System Network Configuration Discovery | T1016 | Discovery |
| Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | Credential Access |
| Remote Services: SMB/Windows Admin Shares | T1021.002 | Lateral Movement |
| Archive Collected Data: Archive via Utility | T1560.001 | Collection |
| Exfiltration Over Alternative Protocol | T1048.003 | Exfiltration |
| Indicator Removal: Clear Windows Event Logs | T1070.001 | Defense Evasion |

### Detection Opportunities (Per Phase)

| Phase | Top Detection |
|-------|--------------|
| Initial Access | `winword.exe → cmd.exe` parent-child relationship |
| Execution | Encoded PowerShell + process in ProgramData making network calls |
| Persistence | Scheduled task in UpdateOrchestrator path by non-system process |
| Discovery | Burst of recon commands from same process within 60 seconds |
| Credential Access | RC4 TGS request for service account SPN (Kerberoasting) |
| Lateral Movement | PSEXESVC service creation on DC; remote cmd.exe with System integrity |
| Exfiltration | 7z.exe + certutil.exe on DC + large transfer on non-443 port |
| Defense Evasion | wevtutil.exe clearing Security/System/Application logs in sequence |

### Blind Spots

- **Phase 2:** If C2 uses a legitimate cloud provider (GitHub, OneDrive, Slack API), the domain won't be flagged as malicious. Requires behaviour-based detection, not domain reputation alone.
- **Phase 5:** Offline cracking of the Kerberos ticket is entirely invisible in the lab. Only the ticket request is detectable.
- **Phase 6:** NTDS extraction via Volume Shadow Copy (`ntdsutil` + VSS) is only a strong signal if Sysmon or similar is monitoring those specific processes on the DC.
- **Phase 7:** Log clearing (`wevtutil cl`) destroys the very logs that would show earlier phases. In environments without a SIEM forwarding logs in real time, the evidence chain is broken.

### How to Run

```bash
# Full kill chain with default settings (~60 events, ~30 seconds runtime)
bash scripts/apt_scenario.sh

# Customise victim environment:
VICTIM_HOST=workstation-08 VICTIM_USER=cjones DOMAIN=ACME DC_HOST=addc-02 \
  bash scripts/apt_scenario.sh

# Use a specific C2 IP (useful for correlation testing):
C2_IP=198.51.100.99 EXFIL_IP=198.51.100.99 bash scripts/apt_scenario.sh
```

### Building an Incident Timeline in Kibana

After running this script, open Kibana Discover and filter on `labels.simulation: attack`. Sort ascending by `@timestamp`. You should see events spanning all 7 phases. Try building a timeline by grouping on `host.name` and `user.name` to see the attacker pivot from the victim workstation to the DC.

---

## 5. Cross-Scenario Notes

### Running Multiple Scenarios

Each script appends to the same log file (`./data/logs/attack-simulation.json`) by default. To keep scenarios isolated, set `LOG_FILE` before running:

```bash
LOG_FILE=./data/logs/c2-test.json bash scripts/c2_beacon_simulation.sh
LOG_FILE=./data/logs/persist-test.json bash scripts/persistence_simulation.sh
```

All events include `labels.simulation: attack` which can be used as a Kibana filter to separate simulation traffic from baseline generator traffic.

### Correlating Events

All process, network, and auth events use consistent `host.name` and `user.name` values within a single script run. You can build a correlated alert in Kibana by:

1. Filter on `labels.simulation: attack` and a specific `host.name`
2. Sort by `@timestamp` ascending
3. Group by `event.category` to see the attack phases

### ECS Field Coverage

The simulations use the following ECS fields that have corresponding detections or dashboard panels:

| ECS Field | Used By |
|---|---|
| `event.category` | All events |
| `event.action` | All events |
| `event.outcome` | Auth, network events |
| `process.name` | Process events |
| `process.parent.name` | Process events |
| `process.command_line` | Process events |
| `process.integrity_level` | Privilege escalation events |
| `source.ip` / `destination.ip` | Network, auth events |
| `destination.port` | Network events |
| `network.bytes` | Network events |
| `authentication.service` | Auth events |
| `authentication.ticket.encryption_type` | Kerberoasting event |
| `registry.path` / `registry.key` | Registry events |
| `dns.question.name` | DNS events |
| `file.path` / `file.directory` | File events |
| `user.name` / `user.domain` | All events |
| `host.name` | All events |
| `labels.simulation` | All events (`attack`) |

### Adding New Scenarios

New simulation scripts should follow the conventions established in the existing scripts:

1. Source `utils.sh` and set `SCRIPT_NAME`
2. Use `make_*` helpers from `utils.sh` for standard event types
3. Use inline `cat <<JSON | write_event "$(cat)"` for specialised event types
4. Include a `log_info` summary at the end listing expected detections and key fields
5. Document the script header with MITRE ATT&CK mappings, usage, and expected detections
6. Keep default `BEACON_COUNT`, `ATTEMPT_COUNT`, and similar loop variables low enough that the script completes in under 60 seconds for CI compatibility
