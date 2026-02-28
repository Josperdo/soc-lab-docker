# Intermediate Guide: Building a Custom Detection

This guide walks through the full detection engineering process for a threat not already covered by this lab's detection library — **PowerShell encoded command execution**.

The goal is not to hand you a finished query. It's to show how a detection engineer thinks: starting from a threat, moving through the data, building a hypothesis, testing it, and knowing when the detection is good enough.

Prerequisites: Familiarity with Kibana and basic KQL/ES|QL syntax. The [Beginner Guide](BEGINNER_GUIDE.md) covers these if needed.

---

## The Threat: PowerShell Encoded Commands

Attackers frequently execute PowerShell with Base64-encoded command strings:

```powershell
powershell.exe -EncodedCommand JABjAGwAaQBlAG4AdA...
```

The `-EncodedCommand` (or `-enc`) flag accepts a Base64-encoded string and executes it directly. This is a standard evasion technique because:

- The actual command is not visible in plain text in process logs
- Many endpoint controls look for specific keyword patterns that Base64 encoding bypasses
- It's a built-in Windows feature, so no additional tools are needed (living-off-the-land)

**MITRE ATT&CK:** T1059.001 — Command and Scripting Interpreter: PowerShell
**Sub-technique context:** T1027 — Obfuscated Files or Information

---

## Step 1: Threat Research

Before writing a query, understand what the attack looks like at the data level. Key questions:

**What process is involved?**
`powershell.exe` (or `pwsh.exe` on newer systems)

**What field captures the command?**
`process.command_line` — the full command including arguments

**What string pattern distinguishes malicious from legitimate usage?**
The `-EncodedCommand` flag (abbreviated variants: `-enc`, `-en`, `-e`). Legitimate PowerShell rarely uses encoded commands; attacker tooling almost always does.

**What does legitimate usage look like?**
Some enterprise software and deployment scripts use `-EncodedCommand` for legitimate automation. This is your false-positive surface — you need to know it exists so you can tune for it.

---

## Step 2: Explore the Data

Open Kibana → Discover → `soc-lab-*` index → Last 24 hours.

Run a baseline query to see all PowerShell process events:

```
event.category: "process" AND process.name: "powershell.exe"
```

Examine the events. Note which fields are consistently populated:

- `process.name` — always `powershell.exe`
- `process.command_line` — the full command string (this is your detection field)
- `process.parent.name` — what launched PowerShell (explorer.exe, cmd.exe, svchost.exe, etc.)
- `user.name` — who ran it
- `host.name` — which system

Now look specifically for encoded commands:

```
event.category: "process" AND
process.name: "powershell.exe" AND
process.command_line: "*-enc*"
```

If the simulation script has generated any, you'll see them here. If not — that's useful information too. It means this detection covers a gap in the lab's current simulation coverage.

---

## Step 3: Write the Hypothesis

A detection hypothesis is a precise statement of the form:

> When [observable behavior], it indicates [threat], and we should alert when [threshold/condition].

For this detection:

> When a `powershell.exe` process is created with a command line containing `-EncodedCommand`, `-enc`, or `-e` as a standalone flag, it likely indicates obfuscated code execution consistent with T1059.001. Alert on any occurrence — this is rare enough in normal environments that each instance warrants review.

Note the threshold decision: **any occurrence**, not "more than N per hour." Some threats are rare enough that a single event is already suspicious. Encoded PowerShell is one of them in most environments.

---

## Step 4: Write the Query Incrementally

Start broad, then narrow.

**Iteration 1 — Capture everything (too broad):**

```esql
FROM soc-lab-*
| WHERE event.category == "process"
  AND process.name == "powershell.exe"
| LIMIT 100
```

Run it. Note the volume. This is your denominator — how many PowerShell events exist total.

**Iteration 2 — Apply the encoding filter:**

```esql
FROM soc-lab-*
| WHERE event.category == "process"
  AND process.name == "powershell.exe"
  AND process.command_line LIKE "*-enc*"
| LIMIT 100
```

This catches `-enc`, `-encoded`, `-encodedcommand`. Check the results — are there false positives (legitimate scripts using `-enc`)? If yes, examine what distinguishes them.

**Iteration 3 — Add parent process context:**

```esql
FROM soc-lab-*
| WHERE event.category == "process"
  AND process.name == "powershell.exe"
  AND process.command_line LIKE "*-enc*"
| STATS
    event_count   = COUNT(*),
    unique_hosts  = COUNT_DISTINCT(host.name),
    unique_users  = COUNT_DISTINCT(user.name)
  BY process.parent.name, user.name, host.name
| SORT event_count DESC
| LIMIT 100
```

Parent process context is critical for triage. PowerShell spawned by:
- `explorer.exe` — interactive user session, possible but worth reviewing
- `cmd.exe` or `wscript.exe` — scripted execution, higher suspicion
- `svchost.exe` or `services.exe` — service-launched, very high suspicion
- `WmiPrvSE.exe` — WMI-launched, almost certainly malicious

**Iteration 4 — The production query:**

```esql
FROM soc-lab-*
| WHERE event.category == "process"
  AND process.name == "powershell.exe"
  AND process.command_line LIKE "*-enc*"
| EVAL
    is_suspicious_parent = CASE(
      process.parent.name IN ("wscript.exe", "cscript.exe", "mshta.exe",
                               "WmiPrvSE.exe", "svchost.exe"), true,
      false
    )
| STATS
    event_count        = COUNT(*),
    suspicious_parents = SUM(CASE WHEN is_suspicious_parent == true THEN 1 ELSE 0 END),
    seen_parents       = COUNT_DISTINCT(process.parent.name),
    affected_hosts     = COUNT_DISTINCT(host.name)
  BY user.name, host.name
| SORT suspicious_parents DESC, event_count DESC
| LIMIT 100
```

This adds a `suspicious_parents` column — events where the parent process is inherently unusual. This lets you triage: investigate `suspicious_parents > 0` first, then review remaining events.

---

## Step 5: Generate Test Data

The existing simulation scripts don't cover encoded PowerShell. Add a test event manually using the lab's `utils.sh` helper:

```bash
source scripts/utils.sh

# Simulate an encoded PowerShell process event
# Signature: make_process_event <parent> <child> <cmdline> <username> <hostname>
event=$(make_process_event \
  "wscript.exe" \
  "powershell.exe" \
  "powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0" \
  "attacker_user" \
  "WORKSTATION-04")

write_event "$event"
```

Re-run the query. Verify the event appears and the `suspicious_parents` column correctly flags it.

---

## Step 6: Document the Detection

Every detection should be self-documenting. Create a new file at `detections/lateral_movement/powershell_encoded_command.kql`:

```kql
// ============================================================
// Detection: PowerShell Encoded Command Execution
// ============================================================
// Purpose:    Detects PowerShell launched with Base64-encoded
//             command strings — a common obfuscation technique
//             used to hide malicious payloads from string-based
//             detection controls.
//
// MITRE ATT&CK: T1059.001 – Command and Scripting: PowerShell
//               T1027     – Obfuscated Files or Information
//
// Required Fields:
//   event.category       (process)
//   process.name         (powershell.exe)
//   process.command_line (contains -enc / -encodedcommand)
//   process.parent.name
//   user.name
//   host.name
//
// Threshold:
//   Any occurrence — encoded PowerShell is rare enough in most
//   environments that each instance warrants investigation.
//
// Tuning Guidance:
//   - Whitelist known deployment scripts that legitimately use
//     -EncodedCommand (document the business justification)
//   - Prioritize events where process.parent.name is a scripting
//     engine or WMI host over interactive user sessions
//   - Combine with network events on the same host/timeframe
//     to detect if the encoded script made outbound connections
//
// False Positive Sources:
//   - Enterprise software deployment tools (SCCM, Intune)
//   - Vendor-supplied scripts that use encoding for special characters
//   - PowerShell DSC (Desired State Configuration) in some configs
//
// Last updated: 2026-02-27
// ============================================================

FROM soc-lab-*
| WHERE event.category == "process"
  AND process.name == "powershell.exe"
  AND process.command_line LIKE "*-enc*"
| EVAL
    is_suspicious_parent = CASE(
      process.parent.name IN ("wscript.exe", "cscript.exe", "mshta.exe",
                               "WmiPrvSE.exe", "svchost.exe"), true,
      false
    )
| STATS
    event_count        = COUNT(*),
    suspicious_parents = SUM(CASE WHEN is_suspicious_parent == true THEN 1 ELSE 0 END),
    seen_parents       = COUNT_DISTINCT(process.parent.name),
    affected_hosts     = COUNT_DISTINCT(host.name)
  BY user.name, host.name
| SORT suspicious_parents DESC, event_count DESC
| LIMIT 100
```

---

## Step 7: Know When to Stop

A detection is not finished when the query runs — it's finished when you can answer:

| Question | Answer for this detection |
|---|---|
| What does it catch? | PowerShell with `-enc` / `-encodedcommand` flags |
| What does it miss? | Alternative encoding approaches (e.g., `[char]` concatenation, `invoke-expression`) |
| What are the false positives? | Legitimate deployment tools |
| How do I tune it? | Whitelist specific parent processes or command-line patterns |
| What's the response? | Investigate the decoded Base64 payload; check for network activity |

Every production detection lives with these trade-offs. The goal is not a perfect query — it's a query whose limitations you understand well enough to operate safely.

---

## What You Just Did

- Researched a threat technique before touching a query editor
- Explored the data to understand the field structure
- Wrote a formal hypothesis — which forced you to make threshold decisions explicitly
- Built the query in iterations, starting broad and adding precision
- Generated test data to validate
- Documented trade-offs alongside the query itself

This is the methodology that scales. The same process works whether you're writing your 5th detection or your 500th.

---

## Going Further

- Try converting this detection to a Sigma rule using the format in `detections/sigma/`
- Add a corresponding alert rule definition in `alerts/rules/`
- Add an Azure Sentinel analytics rule resource to `terraform/sentinel/analytics_rules.tf` for this detection
