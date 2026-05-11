# EDR Remediation System: Complete End-to-End Documentation

**Document Version:** 1.0  
**Last Updated:** 2026-05-10  
**Scope:** Full remediation pipeline from PAT construction to LLM reasoning

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [System Architecture Overview](#system-architecture-overview)
3. [Phase 1: Process Artifact Tree (PAT) Construction](#phase-1-process-artifact-tree-pat-construction)
4. [Phase 2: Incident Detection & Grouping](#phase-2-incident-detection--grouping)
5. [Phase 3: Context Assembly](#phase-3-context-assembly)
6. [Phase 4: RemediationAgent ReAct Loop](#phase-4-remediationagent-react-loop)
7. [Phase 5: LLM Structured Output](#phase-5-llm-structured-output)
8. [Data Flow Diagram](#data-flow-diagram)
9. [Known Issues & Improvements](#known-issues--improvements)

---

## Executive Summary

The **EDR Remediation System** is a **post-containment forensic sweep** pipeline that runs AFTER the AnalystAgent has triaged and contained an incident. It is completely separate from real-time graph-based triage.

### Key Principle
```
AnalystAgent (real-time)       → Is this malicious? KILL IT NOW.
RemediationAgent (post-hoc)    → What did the attacker leave behind?
```

### The Pipeline at a Glance

```
1. PAT is built continuously (parallel with Memgraph graph building)
   ↓
2. After log ingestion completes + 60s grace period:
   Query Memgraph for actioned GUIDs (pending_action IS NOT NULL)
   ↓
3. Cluster actioned GUIDs by shared PAT ancestry (union-find)
   ↓
4. For each cluster:
   a. Walk PAT upward (ancestry) + downward (blast radius)
   b. Assemble JSON context payload
   c. Launch RemediationAgent ReAct loop
   d. Agent calls forensic tools on PAT
   e. LLM produces final structured report
   ↓
5. Report written to disk (remediation_reports/<incident_id>.json)
```

---

## System Architecture Overview

### High-Level Components

```
┌─────────────────────────────────────────────────────────────────┐
│                    REMEDIATION MODULE                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  IncidentCollector                                               │
│  └─ Queries Memgraph for ProcessInstance nodes with             │
│     pending_action stamped by AnalystAgent                       │
│                                                                   │
│  IncidentGrouper (uses UnionFind)                                │
│  └─ Clusters GUIDs sharing PAT ancestry into logical incidents   │
│                                                                   │
│  LineageBuilder                                                  │
│  └─ Expands IncidentGroup with full PAT context:               │
│     - ancestry chain (root → leaf)                              │
│     - blast radius (flagged node + descendants)                 │
│     - injection victims                                          │
│                                                                   │
│  ContextBuilder                                                  │
│  └─ Assembles JSON payload for RemediationAgent                 │
│     - analyst reasoning (from Memgraph)                         │
│     - executed actions (simulated from analyst findings)        │
│     - lineage + process action summaries                        │
│                                                                   │
│  RemediationAgent (ReAct loop)                                   │
│  └─ Drives Gemini LLM with tool-calling:                        │
│     - get_file_activity                                         │
│     - get_network_activity                                      │
│     - get_registry_changes                                      │
│     - get_process_identity                                      │
│     - get_injection_chains                                      │
│     - get_loaded_drivers                                        │
│     - get_process_tampering                                     │
│     - get_child_processes                                       │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘

DATA SOURCES
════════════
  Memgraph                           Redis (PAT)
  ├─ pending_action (analyst)        ├─ process identity (hash)
  ├─ action_reason                   ├─ action stream (ordered)
  └─ action_stamped_at               ├─ parent/child indexes
                                     ├─ file/IP/domain indexes
                                     └─ TTL = 7 days
```

---

## Phase 1: Process Artifact Tree (PAT) Construction

### What is the PAT?

The **Process Artifact Tree (PAT)** is a **Redis-backed forensic ledger** that captures **EVERY Sysmon event** for **EVERY process**, WITHOUT filtering.

Unlike the Memgraph threat graph (which is:
- Sparse (only nodes scored above threshold)
- Pruned (old nodes deleted)
- Sigma-gated (anomaly rules applied)

), the PAT is:
- **Exhaustive** — ALL events for ALL processes
- **Append-only** — Stream never truncated (except for max-length cap)
- **Unfiltered** — No sigma gate, no score gate
- **Persistent** — 7-day TTL independent of Memgraph pruning

### Redis Key Layout

```
pat:identity:{guid}       → Hash    | static metadata + trust signals
pat:actions:{guid}        → Stream  | ordered append-only action log
pat:host_index:{host_id}  → Set     | all GUIDs seen on a host
pat:children:{guid}       → Set     | direct child GUIDs
pat:file_index:{path}     → Set     | GUIDs that touched this file
pat:ip_index:{ip}         → Set     | GUIDs that connected to this IP
pat:dns_index:{domain}    → Set     | GUIDs that queried this domain
```

### Identity Hash Fields

Every process record is stored in `pat:identity:{guid}`:

```python
{
    "guid":            "ProcessGuid from Sysmon",
    "image":           "lower-cased binary path",
    "image_path":      "original-case path for suspicious location detection",
    "parent_guid":     "ParentProcessGuid — enables ancestry walk",
    "parent_image":    "parent's binary name",
    "cmdline":         "full command line",
    "user":            "SID of process owner",
    "pid":             "ProcessId",
    "host_id":         "Computer name",
    "start_time":      "UtcTime when process created",
    "end_time":        "UtcTime when process terminated (empty if alive)",
    "alive":           "true | false",
    
    # TRUST SIGNALS (for pivot-point detection)
    "integrity_level": "System | High | Medium | Low | Untrusted",
    "signature":       "signer / company name (empty if unsigned)",
    "signed":          "true | false | empty",
}
```

### Action Stream Format

The `pat:actions:{guid}` Redis Stream stores timestamped events:

```python
{
    "type":     "event action type",
    "ts":       "UtcTime",
    # ... action-specific fields ...
}
```

**Action types covered:**

| Event Type | Action Type | Fields |
|---|---|---|
| 1 (ProcessCreate) | `child_spawned` | child_guid, child_image, child_cmdline |
| 2 (FileCreateTime) | `file_timestomped` | path, sha256 |
| 3 (NetworkConnect) | `network_connection` | dst_ip, dst_port, src_ip, src_port, protocol, dst_host, initiated |
| 5 (ProcessTerminate) | (identity only) | alive=false, end_time |
| 6 (DriverLoad) | `driver_loaded` | sha256, image_loaded, signed, signature |
| 7 (ImageLoad) | `image_loaded` | image_loaded, sha256, signed, signature |
| 8 (CreateRemoteThread) | `injected_thread_into`, `received_injected_thread` | target_guid, start_address, start_module, start_function |
| 10 (ProcessAccess) | `accessed_process_memory`, `memory_was_accessed_by` | target_guid, access_mask |
| 11 (FileCreate) | `file_created` | path, sha256 |
| 12-14 (Registry) | `registry_write` | reg_type (add/set/rename), key, details, new_name |
| 15 (ADS) | `wrote_ads` | path, stream_name, sha256 |
| 22 (DNSQuery) | `dns_query` | query, results, status |
| 23 (FileDelete) | `file_deleted` | path, sha256, archived |
| 25 (ProcessTampering) | `tampered_process`, `was_tampered_by` | target_guid, tamper_type |

### PAT Construction Algorithm

When `pat.process_event(event)` is called:

```
1. Extract event_id
2. Dispatch to handler (Event 1, 3, 8, etc.)
3. For ProcessCreate (Event 1):
   - Write parent identity (HSETNX — no-op if already written)
   - Append "child_spawned" action to parent stream
   - Write child identity with parent_guid (enables ancestry walk)
4. For all other events:
   - Call _ensure_identity() — HSETNX identity if missing
   - Append action to process stream
   - Populate reverse indexes (file_index, ip_index, dns_index)
   - Refresh TTL on identity + action keys
5. Index maintenance:
   - file_index[path] ← guid  (for artifact→process lookup)
   - ip_index[ip] ← guid
   - dns_index[domain] ← guid
   - host_index[host] ← guid
   - children_index[parent_guid] ← guid
```

### Key Design Decisions

**Trust Field Storage (Event 1 only):**
- Only Event 1 (ProcessCreate) has access to `Signature`, `Company`, `Signed`, `IntegrityLevel`
- These are written once (HSETNX) and never overwritten
- Later events use `_ensure_identity()` which is a no-op if Event 1 already ran
- **Why?** Protects against log injection; first definition wins

**Original-case image_path:**
- Sysmon provides `Image` in original case
- PAT stores both `image` (lowercased) and `image_path` (original)
- Lowercase for lookups; original case for suspicious-path detection
- Detects tricks like `C:\\users\\public\\malware.exe`

**TTL = 7 days:**
- Independent of Memgraph pruning (which is configurable)
- Gives remediation agent a full week to investigate after incident timestamp
- Reverse indexes auto-expire when parent key expires

---

## Phase 2: Incident Detection & Grouping

### Step 1: IncidentCollector

When remediation pipeline starts, the IncidentCollector queries Memgraph:

```sql
MATCH (p:ProcessInstance)
WHERE p.pending_action IS NOT NULL
  AND p.pending_action <> ''
RETURN p.id AS guid, p.pending_action, p.score, p.alive
```

**Output:** List of GUIDs stamped by AnalystAgent with remediation actions.

**Logged:** Every actioned node is logged with:
- guid
- pending_action (e.g., "KILL", "QUARANTINE")
- score (threat score)
- alive (is process still running?)

### Step 2: IncidentGrouper (Union-Find)

The IncidentGrouper clusters actioned GUIDs by shared PAT ancestry:

```
Algorithm:
──────────
1. For each actioned GUID:
   a. Walk PAT upward: guid → parent_guid → parent's parent → ... → root
   b. Collect full ancestry chain
   c. Log the chain for verification

2. Union every (guid, ancestor) pair in UnionFind:
   - If GUID-A and GUID-B share ANY ancestor, they merge

3. Find connected components:
   - GUIDs in same component = one IncidentGroup

4. Per component, find deepest common ancestor:
   - This becomes root_guid for that group
   - Used by LineageBuilder to fetch blast-radius
```

**Why union-find?**
- Transitive: if A→root and B→root share an ancestor, A and B merge automatically
- Efficient: path compression + union by rank
- Transparent: every merge is logged so you can trace which ancestor caused clustering

**Example:**

```
Parent (root)
  ├─ Child-A (flagged ✓)
  ├─ Child-B (flagged ✓)
  │  └─ Grandchild-B1 (flagged ✓)
  └─ Child-C (not flagged)

IncidentGrouper result:
  IncidentGroup(
    incident_id = auto-uuid,
    root_guid = Parent,
    member_guids = [Child-A, Child-B, Grandchild-B1]
  )
```

All three flagged GUIDs are in ONE incident because they share the Parent ancestor.

---

## Phase 3: Context Assembly

### Step 3: LineageBuilder

For each IncidentGroup, LineageBuilder calls:

```python
pat.build_remediation_context(root_guid, max_depth=20)
```

This returns:

```python
{
    "ancestry_chain": [
        # root → flagged node, each with identity + ALL raw actions
        {
            "guid": "...",
            "image": "...",
            "cmdline": "...",
            "user": "...",
            "pid": "...",
            "host_id": "...",
            "start_time": "...",
            "end_time": "...",
            "alive": true/false,
            "integrity_level": "...",
            "signature": "...",
            "signed": "...",
            "actions": [
                {"type": "child_spawned", "ts": "...", ...},
                {"type": "network_connection", "ts": "...", ...},
                ...
            ]
        },
        # ... more nodes ...
    ],
    
    "blast_radius": [
        # flagged node + all descendants (downward BFS)
    ],
    
    "injection_victims": [
        # processes outside blast_radius that received injected thread
    ],
    
    "chain_truncated": false,  # true if walk hit missing PAT key
}
```

**Blast Radius Calculation:**

```
BFS from root_guid:
  visited = {root_guid}
  queue = [root_guid]
  
  while queue not empty:
    node = pop(queue)
    blast_radius.append(node)
    for child in pat.get_children(node):
      if child not in visited:
        visited.add(child)
        queue.append(child)
```

This captures:
- The originally flagged process
- All its children spawned during the incident
- All their children (recursively)
- **Excludes** processes outside the lineage

### Step 4: ContextBuilder

ContextBuilder assembles the JSON payload that RemediationAgent receives:

```python
{
    "incident_id": "uuid",
    "root_guid": "ProcessGuid",
    "member_guids": ["guid1", "guid2", ...],
    "chain_truncated": false,
    
    # From Memgraph
    "analyst_reasoning": [
        {
            "guid": "...",
            "pending_action": "KILL",
            "action_reason": "Detected IOC: shadow.exe running from %TEMP%",
            "action_stamped_at": "2026-05-10T14:30:00Z",
            "pid": 1234,
            "score": 0.95,
            "alive": false,  # AnalystAgent killed it
        },
        ...
    ],
    
    # Simulated execution (what IF these actions ran)
    "executed_actions": [
        {
            "action": "KILL",
            "target_type": "process",
            "target_value": "guid1",
            "executed_at": "2026-05-10T14:30:05Z",
            "status": "EXECUTED",
        },
        ...
    ],
    
    # Full lineage from PAT
    "lineage": {
        "ancestry_chain": [...],  # identity + actions for each
        "blast_radius": [...],
    },
    
    # Abbreviated action summary per process (full streams in tool log)
    "process_action_summaries": [
        {
            "guid": "...",
            "image": "shadow.exe",
            "notable_actions": [
                {"type": "file_created", "path": "C:\\...\\backdrop.dll", "ts": "..."},
                {"type": "registry_write", "key": "HKCU\\Software\\...", "ts": "..."},
                ...
            ],
        },
        ...
    ],
    
    "injection_victims": [...],
}
```

**What gets logged at this stage:**
- Full context_payload (with actions streamed stripped for brevity)
- lineage_summary (ASCII tree of ancestry + blast radius + victims)

---

## Phase 4: RemediationAgent ReAct Loop

### Agent Overview

The **RemediationAgent** is a ReAct (Reasoning + Acting) loop that drives an LLM (Gemini) to reason about the incident and call forensic tools.

```
Agent Architecture:
───────────────────

1. Initialize
   - Load system prompt
   - Connect to Gemini 3.1 Flash Lite Preview
   - Load 8 forensic tool declarations

2. ReAct Loop (max 10 rounds)
   Round 1:
     a. Send initial_message (full context payload)
     b. Receive response with potential function calls
   
   Round N (while rounds < 10):
     a. Check response.function_calls
     b. If no calls → LLM finished reasoning, FORCE FINAL
     c. For each call:
        - Extract tool name + args
        - Execute against PAT
        - Log to remediation_log
        - Build response part
     d. Send all results back in one turn

3. Force Final Report
   - If loop exited naturally (no function calls):
     Send schema-only call to Gemini to extract structured JSON
   - If max rounds hit:
     Send schema-only call anyway (fallback)

4. Parse & Save
   - Parse JSON report
   - Enrich with metadata (incident_id, root_guid, tool_call_log)
   - Write to remediation_reports/{incident_id}.json
```

### System Prompt

The RemediationAgent's system prompt instructs the LLM to be a **post-containment forensic responder**:

```
You are a senior forensic incident responder. Your role is POST-CONTAINMENT SWEEP.

The Analyst Agent has already triaged and issued initial containment
(process kills, IP/domain blocks). Your job is NOT to re-triage. It is to answer:

  1. PERSISTENCE  — Did the attacker plant mechanisms that survive reboot?
                    (Run keys, startup files, scheduled tasks, services, WMI, DLL hijacking)
                    Are they STILL ACTIVE?

  2. EXFILTRATION — Was data sent out? To which IPs/domains? Estimate what was stolen.

  3. BACKDOORS    — Are any injected threads, hollowed processes, rogue drivers
                    still resident in memory or on disk?

  4. CLEANUP      — Produce a prioritised, machine-executable cleanup action list.

  5. IOC LIST     — Extract every artefact usable for hunting on other hosts.

TOOL USAGE STRATEGY:
  - MUST call tools before concluding. Never invent data.
  - Start with blast_radius_guids. Call get_file_activity, get_registry_changes
    on every process.
  - Call get_network_activity to find C2/exfil endpoints.
  - If you find injections, call get_injection_chains.
  - If you find suspicious children, call get_child_processes then investigate.
  - Base every finding strictly on tool results. Never guess.
  - If a tool returns empty results, note "no activity observed" and move on.
  - Severity: critical = active threat present; high = significant residual risk;
    medium = cleanup needed but no active threat; low = informational.
```

### Remediation Tools (8 available)

Each tool queries the PAT and returns a clean, structured dict:

#### 1. **get_file_activity(guid)**

```python
{
    "guid": "...",
    "total_file_events": 42,
    "created": [
        {
            "path": "c:\\users\\admin\\appdata\\temp\\backdrop.dll",
            "sha256": "abc123...",
            "ts": "2026-05-10T10:15:00Z",
            "suspicious": true  # ← flagged by path keyword matching
        },
        ...
    ],
    "deleted": [...],
    "timestomped": [...],
    "ads_written": [...],
    "suspicious_paths": [
        "c:\\users\\admin\\appdata\\temp\\backdrop.dll",
        "c:\\programdata\\microsoft\\windows\\start menu\\programs\\startup\\evil.lnk",
        ...
    ],
}
```

**Suspicious path detection:**
- Keyword matching against known persistence locations:
  - `\appdata\roaming\...\startup`
  - `\windows\temp`, `\users\public`
  - `system32\tasks`, `syswow64\tasks`
  - etc.

#### 2. **get_network_activity(guid)**

```python
{
    "guid": "...",
    "connections": [
        {
            "dst_ip": "192.0.2.123",
            "dst_port": "443",
            "dst_host": "c2.evil.com",
            "src_ip": "10.0.0.50",
            "src_port": "54321",
            "protocol": "tcp",
            "initiated": "true",
            "ts": "2026-05-10T10:16:30Z",
            "external": true  # ← not RFC-1918 / loopback
        },
        ...
    ],
    "dns_queries": [
        {
            "query": "c2.evil.com",
            "results": "192.0.2.123",
            "status": "Success",
            "ts": "2026-05-10T10:16:20Z",
        },
        ...
    ],
    "external_ips": ["192.0.2.123", "203.0.113.45"],
    "external_domains": ["c2.evil.com", "exfil.attacker.net"],
    "total_connections": 15,
    "total_dns_queries": 8,
}
```

**External IP/domain detection:**
- IPs NOT in RFC-1918 / loopback ranges
- Domains NOT ending in `.local`, `.internal`, `.corp`

#### 3. **get_registry_changes(guid)**

```python
{
    "guid": "...",
    "total_registry_writes": 23,
    "writes": [
        {
            "reg_type": "set",  # "add" | "set" | "rename"
            "key": "hkcu\\software\\microsoft\\windows\\currentversion\\run",
            "details": "C:\\Users\\admin\\malware.exe",
            "new_name": "",
            "ts": "2026-05-10T10:14:00Z",
            "suspicious": true  # ← keyword matched
        },
        ...
    ],
    "suspicious_keys": [
        "hkcu\\software\\microsoft\\windows\\currentversion\\run",
        "hklm\\system\\currentcontrolset\\services\\...",
        ...
    ],
}
```

**Suspicious registry keywords:**
- `currentversion\run` (auto-start)
- `currentversion\runonce`
- `winlogon`, `userinit`, `shell`, `load`
- `services\`, `schedlgu`, `image file execution options`
- `appinit_dlls`, `lsa\`

#### 4. **get_process_identity(guid)**

Returns the static identity hash for a GUID (useful for LLM pivot-point detection):

```python
{
    "guid": "...",
    "image": "shadow.exe",
    "image_path": "C:\\Users\\Public\\shadow.exe",
    "parent_guid": "...",
    "parent_image": "explorer.exe",
    "cmdline": "shadow.exe -c http://c2.evil.com",
    "user": "s-1-5-21-...-500",  # SID (low = admin)
    "pid": "2048",
    "host_id": "WORKSTATION-01",
    "start_time": "2026-05-10T10:10:00Z",
    "end_time": "2026-05-10T10:30:00Z",
    "alive": false,
    "integrity_level": "Medium",
    "signature": "",  # unsigned
    "signed": "false",
}
```

#### 5. **get_injection_chains(guid)**

Finds all thread injections performed by or received by a process:

```python
{
    "guid": "...",
    "injected_into": [
        {
            "target_guid": "...",
            "target_image": "svchost.exe",
            "start_address": "0x140000000",
            "start_module": "ntdll.dll",
            "start_function": "RtlUserThreadStart",
            "ts": "2026-05-10T10:20:00Z",
        },
        ...
    ],
    "received_from": [...],
    "total_injections_out": 2,
    "total_injections_in": 0,
}
```

#### 6. **get_loaded_drivers(guid)**

Returns all kernel drivers and DLLs loaded by a process:

```python
{
    "guid": "...",
    "drivers": [
        {
            "image_loaded": "C:\\Windows\\System32\\hal.sys",
            "sha256": "...",
            "signed": "true",
            "signature": "Microsoft Corporation",
            "ts": "2026-05-10T10:10:30Z",
            "suspicious": false,
        },
        {
            "image_loaded": "C:\\Users\\Public\\rogue.sys",
            "sha256": "...",
            "signed": "false",
            "signature": "",
            "ts": "2026-05-10T10:15:00Z",
            "suspicious": true,  # unsigned + path unusual
        },
        ...
    ],
    "dlls": [...],
    "unsigned_drivers": ["C:\\Users\\Public\\rogue.sys"],
}
```

#### 7. **get_process_tampering(guid)**

Finds hollow-process, herpadering, and other tampering:

```python
{
    "guid": "...",
    "tampered_targets": [
        {
            "target_guid": "...",
            "target_image": "notepad.exe",
            "tamper_type": "Hollowing",
            "ts": "2026-05-10T10:18:00Z",
        },
        ...
    ],
    "tampered_by": [
        {
            "source_guid": "...",
            "source_image": "shadow.exe",
            "tamper_type": "Injection",
            "ts": "2026-05-10T10:18:00Z",
        },
        ...
    ],
}
```

#### 8. **get_child_processes(guid)**

Returns all child processes spawned by a GUID:

```python
{
    "guid": "...",
    "children": [
        {
            "child_guid": "...",
            "child_image": "cmd.exe",
            "child_cmdline": "cmd.exe /c whoami",
            "ts": "2026-05-10T10:12:00Z",
        },
        ...
    ],
    "total_children": 5,
}
```

### ReAct Loop Example

**Round 1:**
- Agent receives context payload + incident overview
- Sends message to Gemini
- Gemini responds: "I need to investigate file activity in the blast radius. Calling get_file_activity for the main process..."
- Agent extracts function call: `get_file_activity(guid="process-A")`

**Round 2:**
- Agent calls `get_file_activity("process-A")` → returns dict with suspicious files
- Agent logs the full call + result
- Agent sends result back to Gemini
- Gemini: "Interesting! There's a DLL in the temp folder. Let me check network activity..."
- Agent extracts: `get_network_activity(guid="process-A")`

**Round 3:**
- Agent calls tool, logs result
- Gemini: "Ah, C2 connections to evil.com. Let me check if child processes did the same..."
- Agent extracts: `get_child_processes(guid="process-A")`

**(continues up to 10 rounds)**

**After final round or no tool calls:**
- Agent detects LLM finished reasoning
- Calls force_final_report() with accumulated reasoning
- Gemini generates structured JSON via schema-only call

### Logging at Each Stage

Every agent execution is logged to the remediation logger:

```
remediation_logs/
  ├─ remediation_yyyy-mm-dd_HHmmss.log  ← main log file
  └─ Contains:
      - Initial context payload
      - Opening prompt (full incident summary)
      - Each round: round number, timestamp
      - Each tool call: name, args, full result
      - Final force-final prompt
      - Final structured response from LLM
```

---

## Phase 5: LLM Structured Output

### Final Report Schema

After ReAct loop or max rounds, the agent forces a final schema-constrained call:

```python
{
    "findings": [
        {
            "category": "persistence" | "exfiltration" | "backdoor" | "lateral_movement" | "other",
            "severity": "critical" | "high" | "medium" | "low",
            "guid": "ProcessGuid",
            "description": "Human-readable explanation",
            "iocs": ["ioc1", "ioc2", ...],  # extracted from tool results
        },
        ...
    ],
    
    "cleanup_actions": [
        {
            "priority": 1,  # integer, lower = higher priority
            "action_type": "delete_file" | "quarantine_file" | "remove_registry_key"
                         | "block_ip" | "block_domain" | "disable_service"
                         | "scan_process" | "revoke_credential" | "patch_vulnerability"
                         | "reimage_host" | "alert_analyst",
            "target": "specific_path_or_value",
            "reason": "why this cleanup is necessary",
        },
        ...
    ],
    
    "ioc_list": [
        "file_hash_1",
        "192.0.2.123",
        "c2.evil.com",
        "registry_key_path",
        "process_cmdline_pattern",
        ...
    ],
    
    "narrative": "Professional incident response summary (2-3 paragraphs)",
}
```

### RemediationReport (Python Dataclass)

After parsing the LLM response, a RemediationReport is created:

```python
@dataclass
class RemediationReport:
    incident_id: str
    root_guid: str
    findings: List[RemediationFinding]
    cleanup_actions: List[Dict[str, Any]]
    ioc_list: List[str]
    narrative: str
    raw_llm_response: str
    tool_call_log: List[Dict[str, Any]]
    agent_logs: str  # full remediation log
```

### Report Output

The report is written to disk:

```
remediation_reports/
  └─ {incident_id}.json
     {
         "incident_id": "...",
         "root_guid": "...",
         "findings": [...],
         "cleanup_actions": [...],
         "ioc_list": [...],
         "narrative": "...",
         "tool_call_log": [
             {
                 "round": 1,
                 "tool": "get_file_activity",
                 "args": {"guid": "..."},
                 "result": {...}
             },
             ...
         ],
     }
```

---

## Data Flow Diagram

```
SYSMON EVENTS
     ↓
     ↓ [EVERY event, no filter]
     ↓
PAT BUILDER (Redis)
├─ pat:identity:{guid} → process metadata + trust signals
├─ pat:actions:{guid} → ordered action stream
├─ pat:host_index, pat:children_index, pat:file_index, etc.
└─ TTL = 7 days (independent of Memgraph)

     ↓ [Log replay completes]
     ↓ [Sleep 60 seconds]
     ↓
MEMGRAPH THREAT GRAPH
├─ ProcessInstance nodes stamped by AnalystAgent
├─ pending_action = "KILL" | "QUARANTINE" | etc.
└─ action_reason = forensic justification

     ↓
INCIDENT COLLECTOR
└─ Query Memgraph for GUIDs with pending_action IS NOT NULL
   ↓ [1-N GUIDs]

INCIDENT GROUPER (UnionFind)
└─ Cluster GUIDs by shared PAT ancestry
   ↓ [M incident groups]

LINEAGE BUILDER (for each group)
├─ walk PAT ancestry chain (root → flagged)
├─ walk PAT blast radius (flagged + descendants)
└─ identify injection victims
   ↓ [IncidentLineage with full PAT context]

CONTEXT BUILDER (for each lineage)
├─ fetch analyst_reasoning from Memgraph
├─ fetch executed_actions (simulated)
├─ build process_action_summaries from PAT
└─ assemble JSON payload
   ↓ [IncidentContext dict]

REMEDIATION AGENT (ReAct loop)
├─ send initial_message to Gemini
├─ Gemini calls tools (up to 10 rounds)
│  ├─ get_file_activity(guid)  → queries PAT
│  ├─ get_network_activity(guid) → queries PAT
│  ├─ get_registry_changes(guid) → queries PAT
│  ├─ ... (6 more tools)
│  └─ Each result logged + sent back to Gemini
├─ Gemini finishes reasoning
└─ Force final structured call → JSON report
   ↓ [RemediationReport]

REPORT OUTPUT
└─ remediation_reports/{incident_id}.json
   └─ Ready for analyst review + action
```

---

## Known Issues & Improvements

### Issue 1: PAT Identity Trust Fields Only from Event 1

**Problem:**
- Only Sysmon Event 1 (ProcessCreate) includes `Signed`, `Signature`, `Company`, `IntegrityLevel`
- Other events have no access to these fields
- If Event 1 is missing or delayed, identity record has empty trust fields

**Impact:**
- Incomplete pivot-point detection for processes not directly spawned (inherited from parent)
- Less accurate "is this legitimate?" reasoning

**Potential Fix:**
- Query Windows Registry for Signatures on-demand when Event 1 is missing
- Cache results in PAT (e.g., `pat:signatures:{image_hash}`)
- Trade-off: adds registry I/O but improves trust signal completeness

**Implementation hint:**
```python
def _enhance_trust_signals_on_demand(self, guid: str, image_path: str):
    """If trust fields are empty, try to get them from system or cache."""
    identity = self.get_identity(guid)
    if identity and not identity.get("signed"):
        # Query registry or file system, cache result
        pass
```

---

### Issue 2: Chain Truncation Unhandled

**Problem:**
- If a process predates PAT monitoring or TTL expires, ancestry walk stops early
- `chain_truncated = true` is returned but remediation agent doesn't handle it well
- May miss crucial root-cause information

**Impact:**
- Incidents where attacker's initial implant is older than PAT TTL appear disconnected
- LLM gets incomplete context for blast-radius estimation

**Potential Fix:**
- Query Memgraph for older ProcessInstance nodes (outside PAT TTL)
- Merge PAT context with graph context when chain is truncated
- Mark merged data with provenance ("from graph" vs "from PAT")

**Implementation hint:**
```python
def build_remediation_context_with_graph_fallback(self, flagged_guid: str, graph: Memgraph):
    """Walk PAT ancestry; if truncated, continue from Memgraph graph."""
    pat_chain = self.get_parent_chain(flagged_guid)
    if not pat_chain or pat_chain[-1] is not root:
        # Find oldest PAT node, query graph for its parent
        tail = pat_chain[-1] if pat_chain else flagged_guid
        graph_ancestors = query_memgraph_ancestors(tail)
        pat_chain.extend(graph_ancestors)
    return pat_chain
```

---

### Issue 3: Injection Victims Incomplete

**Problem:**
- `injection_victims` list is built only from `injected_thread_into` actions in blast_radius
- If victim process has no PAT identity, it's skipped
- Victims that were cleaned up or TTL-expired can't be scanned

**Impact:**
- RemediationAgent doesn't get a complete picture of lateral-movement targets
- May miss infected svchost, rundll32, or other system processes

**Potential Fix:**
- Store victim GUIDs even if no PAT identity exists
- Include "victim_guid_not_found" entries with a flag
- Let LLM know to be cautious about these

**Implementation hint:**
```python
injection_victims = []
for guid in blast_guids:
    for action in self.get_actions_by_type(guid, "injected_thread_into"):
        tgt = action.get("target_guid", "")
        if tgt and tgt not in visited_down:
            tgt_id = self.r.hgetall(self._identity_key(tgt)) or {}
            injection_victims.append({
                "target_guid": tgt,
                "target_image": action.get("target_image", ""),
                "identity_found": bool(tgt_id),
                "ts": action.get("ts", ""),
            })
```

---

### Issue 4: LLM Tool Calls May Be Incomplete or Redundant

**Problem:**
- LLM may call same tool multiple times on same GUID (inefficient)
- LLM may not explore all blast_radius GUIDs (misses activity)
- LLM reasoning is not deterministic (different runs → different findings)

**Impact:**
- Token usage inefficiency
- Non-reproducible results
- May miss persistence mechanisms in child processes

**Potential Fix:**
- Add tool-call deduplication: cache results per (tool, args) per round
- Implement "mandatory coverage" check: force LLM to call all blast_radius GUIDs
- Log LLM's reasoning steps for audit trail

**Implementation hint:**
```python
def _react_loop_with_coverage(self, ...):
    """Ensure LLM investigates all blast_radius GUIDs."""
    blast_guids = ...
    investigated = set()
    
    for round in range(MAX_TOOL_ROUNDS):
        # ... normal loop ...
        
        # After each round, check coverage
        if round % 2 == 0 and investigated < set(blast_guids):
            missing = [g for g in blast_guids if g not in investigated]
            prompt_coverage = (
                f"You haven't investigated these processes yet: {missing}. "
                f"Please call get_file_activity and get_registry_changes for each."
            )
            # Inject into next prompt
```

---

### Issue 5: Registry/File Path Keyword Matching is Brittle

**Problem:**
- Suspicious-path detection uses simple substring matching
- Can have false positives (e.g., `\TEMP\` matches legitimate Windows Temp dir)
- Can have false negatives (new persistence techniques not in keyword list)

**Impact:**
- Analyst must manually filter tool results for relevance
- Legitimate temp files flagged as suspicious
- Novel attacker techniques missed

**Potential Fix:**
- Use ML-based classifier or YARA rules instead of keywords
- Implement MITRE ATT&CK mapping: link findings to specific tactics
- Crowdsource keyword updates from incident database

**Implementation hint:**
```python
# Current (brittle):
def _is_suspicious_path(path: str) -> bool:
    lower = path.lower()
    return any(kw in lower for kw in _PERSISTENCE_PATH_KEYWORDS)

# Better (with context):
def _is_suspicious_path_with_context(path: str, process_image: str, user: str) -> tuple[bool, str]:
    """Return (is_suspicious, reason)."""
    # Rule 1: temp file written by system service → less suspicious
    # Rule 2: temp file written by low-IL process → very suspicious
    # Rule 3: Registry run key modified by rundll32 → very suspicious
    # etc.
    pass
```

---

### Issue 6: Remediation Report Not Actioned Automatically

**Problem:**
- RemediationReport is generated but not automatically executed
- Cleanup actions are recommendations only
- Analyst must manually copy-paste into remediation tools

**Impact:**
- Response time not optimized (human-in-the-loop delay)
- Risk of manual errors in action execution
- Orphaned processes if cleanup actions not completed

**Potential Fix:**
- Implement Response Module to execute cleanup_actions automatically
- Add approval workflow (analyst review → auto-execute)
- Track remediation action success/failure

**Implementation hint:**
```python
class RemediationExecutor:
    """Execute cleanup_actions from RemediationReport."""
    
    def execute_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """Execute one cleanup action, return status."""
        action_type = action["action_type"]
        target = action["target"]
        
        if action_type == "delete_file":
            return self._delete_file(target)
        elif action_type == "remove_registry_key":
            return self._delete_registry_key(target)
        elif action_type == "block_ip":
            return self._block_ip(target)
        # etc.
        
        return {"status": "executed", "action": action_type, "target": target}
```

---

### Issue 7: No Confidence Scoring for Findings

**Problem:**
- Findings have severity (critical/high/medium/low) but no confidence score
- LLM assertions are treated as ground truth
- No way to distinguish "definitely true" vs "likely true"

**Impact:**
- False positives treated as fact
- Analyst can't prioritize among findings
- No audit trail of reasoning confidence

**Potential Fix:**
- Add `confidence` field (0.0-1.0) to RemediationFinding
- LLM explains confidence in narrative
- Filter display by confidence threshold

**Implementation hint:**
```python
@dataclass
class RemediationFinding:
    # ... existing fields ...
    confidence: float  # 0.0-1.0, from LLM structured reasoning
    evidence_count: int  # how many tool results support this finding
    alternative_explanations: List[str]  # what else could cause this
```

---

### Issue 8: No Deduplication of IOCs Across Incidents

**Problem:**
- Each incident generates an IOC list
- IOCs from different incidents are not merged
- No global IOC database to prevent re-infection

**Impact:**
- Analyst must manually de-duplicate IOCs
- Same attacker indicators scattered across multiple reports
- Missed hunting opportunities

**Potential Fix:**
- Maintain global IOC database (SQL or external MISP/ThreatStream)
- On report generation, check IOCs against database
- Flag when new IOC matches previous incident (potential re-infection)

**Implementation hint:**
```python
class IOCDatabase:
    """Store and query IOCs across all remediation reports."""
    
    def add_incident_iocs(self, incident_id: str, iocs: List[str]):
        """Store IOCs with incident provenance."""
        for ioc in iocs:
            self.db.insert("ioc_history", {
                "ioc": ioc,
                "incident_id": incident_id,
                "timestamp": now(),
            })
    
    def find_related_incidents(self, ioc: str) -> List[str]:
        """Return incidents that share this IOC."""
        return self.db.query(
            "SELECT DISTINCT incident_id FROM ioc_history WHERE ioc = ?",
            (ioc,)
        )
```

---

### Issue 9: Memgraph Query for Analyst Reasoning Fragile

**Problem:**
- ContextBuilder queries Memgraph with Cypher that assumes specific schema
- If Memgraph ProcessInstance schema changes, query breaks
- No error recovery if some nodes missing

**Impact:**
- Pipeline fails silently if schema mismatch
- Incomplete context passed to LLM

**Potential Fix:**
- Add schema introspection before queries
- Implement fallback queries with broader matching
- Add comprehensive error logging

---

### Issue 10: No Timeout on LLM Calls

**Problem:**
- RemediationAgent calls Gemini without timeout
- If LLM stalls, entire pipeline blocks
- No graceful degradation

**Impact:**
- Pipeline hangs on network issues or LLM overload
- No partial results if call fails

**Potential Fix:**
- Add timeout to each Gemini call (e.g., 30 seconds per turn)
- Implement exponential backoff on retry
- Fallback to heuristic-based findings if LLM fails

---

## Summary of Recommendations

| Issue | Priority | Effort | Impact |
|-------|----------|--------|--------|
| Injection victims incomplete | High | Medium | Missed lateral-movement targets |
| Chain truncation unhandled | High | Medium | Incomplete root-cause analysis |
| No confidence scoring | Medium | High | False positives treated as fact |
| Tool calls redundant | Medium | Low | Token waste, inefficiency |
| No IOC deduplication | Medium | High | Missed re-infection signals |
| Registry keyword matching brittle | Medium | Medium | False positives/negatives |
| LLM calls unprotected (no timeout) | High | Low | Pipeline stability |
| Remediation not auto-executed | Low | High | Response time not optimized |
| Trust fields from Event 1 only | Medium | Medium | Incomplete pivot-point detection |
| Memgraph query fragile | Medium | Medium | Silent failures |

---

## Conclusion

The EDR Remediation System is a sophisticated multi-stage pipeline that combines:

1. **Exhaustive forensic logging** (PAT in Redis)
2. **Intelligent incident clustering** (union-find on ancestry)
3. **Rich context assembly** (merging Memgraph + PAT)
4. **LLM-driven reasoning** (ReAct loop with 8 forensic tools)
5. **Structured output** (machine-actionable cleanup plans)

The system's strength is its **completeness**: no event is missed, no process is invisible, and the LLM has access to the full ground truth. Its weakness is the **lack of automation** in the final remediation step and the **brittleness** of heuristic-based suspicious-path detection.

The recommended next steps are:
1. Implement chain-truncation fallback to Memgraph
2. Add confidence scoring to findings
3. Implement IOC deduplication database
4. Add timeout protection to LLM calls
5. Develop the Response Module for automatic cleanup execution

---

**Document prepared for:** EDR Engineering Team  
**For questions, contact:** [Forensics Investigation Team]
