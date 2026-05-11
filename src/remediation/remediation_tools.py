"""
remediation_tools.py  —  Tool/Function registry for the RemediationAgent (ReAct interface).

PURPOSE
-------
Defines Python functions that the LLM can call via the ReAct (tool-calling) loop.
Each function queries the PAT (Redis) for a specific category of process activity
and returns a clean, structured dict that the LLM can reason over.

These tools answer the core forensic questions:
  • Did this process write persistence mechanisms (registry, files)?
  • Did this process exfiltrate data to external IPs / domains?
  • Did child processes create backdoors (injections, drivers, ADS)?
  • What DLLs did the process load (suspicious injection vectors)?
  • Was this process itself tampered with (hollowing, herpadering)?

DESIGN NOTES
------------
- Every function is PURE with respect to the LLM: it takes a guid (str),
  returns a JSON-serialisable dict, and never raises (errors are returned
  as {"error": "..."} dicts so the LLM can continue reasoning).
- The PAT is the single data source — no Memgraph queries here.
- Persistence detection uses a keyword allowlist for common persistence paths
  and registry keys so the LLM gets a pre-filtered "suspicious" flag.

GEMINI TOOL SCHEMA
------------------
Each function is wrapped with a schema dict that Gemini function-calling
understands. The schema is assembled in get_tool_declarations().
"""

from __future__ import annotations

from typing import Any, Dict, List

# Persistence indicator keywords — paths and registry keys frequently abused
# for persistence (Run keys, startup folder, scheduled tasks, services, etc.)
_PERSISTENCE_PATH_KEYWORDS = [
    "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup",
    "\\programdata\\microsoft\\windows\\start menu\\programs\\startup",
    "system32\\tasks",
    "syswow64\\tasks",
    "\\temp\\",
    "\\users\\public\\",
    "\\appdata\\local\\temp",
    "\\windows\\temp",
]

_PERSISTENCE_REG_KEYWORDS = [
    "currentversion\\run",
    "currentversion\\runonce",
    "currentversion\\runservices",
    "winlogon",
    "userinit",
    "shell",
    "load",
    "services\\",
    "\\currentcontrolset\\services",
    "schedlgu",
    "image file execution options",
    "appinit_dlls",
    "lsa\\",
]

_EXFIL_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "::1", "fc00::", "fd",
)


def _is_external_ip(ip: str) -> bool:
    """Return True when ip is NOT a RFC-1918 / loopback address."""
    return not any(ip.startswith(p) for p in _EXFIL_PRIVATE_PREFIXES)


def _is_suspicious_path(path: str) -> bool:
    """Return True when the file path matches a known persistence location."""
    lower = path.lower()
    return any(kw in lower for kw in _PERSISTENCE_PATH_KEYWORDS)


def _is_suspicious_reg_key(key: str) -> bool:
    """Return True when the registry key matches a known persistence pattern."""
    lower = key.lower()
    return any(kw in lower for kw in _PERSISTENCE_REG_KEYWORDS)


# ══════════════════════════════════════════════════════════════════════════════
# TOOL FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

class RemediationToolRegistry:
    """
    Holds a reference to the PAT builder and exposes named tool methods.

    Usage
    -----
        registry = RemediationToolRegistry(pat)
        result   = registry.call("get_file_activity", {"guid": "..."})

    The RemediationAgent calls registry.call(tool_name, args_dict) inside
    its ReAct loop — it never calls tool functions directly.
    """

    def __init__(self, pat):
        """
        Parameters
        ----------
        pat : PATBuilder instance (already connected to Redis).
        """
        self._pat = pat

    # ── DISPATCHER ────────────────────────────────────────────────────────────

    def call(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Route a tool call from the LLM to the correct method.

        Parameters
        ----------
        tool_name : one of the registered tool names (see get_tool_declarations).
        args      : dict of arguments as produced by Gemini function-calling.

        Returns
        -------
        JSON-serialisable dict — always, even on error.
        """
        handler = {
            "get_file_activity":      self.get_file_activity,
            "get_network_activity":   self.get_network_activity,
            "get_registry_changes":   self.get_registry_changes,
            "get_process_identity":   self.get_process_identity,
            "get_injection_chains":   self.get_injection_chains,
            "get_loaded_drivers":     self.get_loaded_drivers,
            "get_process_tampering":  self.get_process_tampering,
            "get_child_processes":    self.get_child_processes,
        }.get(tool_name)

        if handler is None:
            return {"error": f"Unknown tool: {tool_name!r}"}

        try:
            return handler(**args)
        except Exception as exc:
            return {"error": str(exc), "tool": tool_name, "args": args}

    # ── TOOL 1: FILE ACTIVITY ─────────────────────────────────────────────────

    def get_file_activity(self, guid: str) -> Dict[str, Any]:
        """
        Query the PAT for all file-system activity by a given process.

        Covers: file_created, file_deleted, file_timestomped, wrote_ads (ADS).

        Each record is annotated with a `suspicious` flag when the path matches
        a known persistence or staging location (Temp, Startup, Tasks, etc.).

        Parameters
        ----------
        guid : ProcessInstance GUID string.

        Returns
        -------
        {
          "guid": str,
          "total_file_events": int,
          "created":     [{"path": str, "sha256": str, "ts": str, "suspicious": bool}],
          "deleted":     [{"path": str, "sha256": str, "ts": str}],
          "timestomped": [{"path": str, "sha256": str, "ts": str}],
          "ads_written": [{"path": str, "stream_name": str, "sha256": str, "ts": str}],
          "suspicious_paths": [str],   # deduplicated list of flagged paths
        }
        """
        created     = []
        deleted     = []
        timestomped = []
        ads_written = []
        suspicious_paths = []

        # --- file_created ---
        for action in self._pat.get_actions_by_type(guid, "file_created"):
            path = action.get("path", "")
            susp = _is_suspicious_path(path)
            if susp:
                suspicious_paths.append(path)
            created.append({
                "path":       path,
                "sha256":     action.get("sha256", ""),
                "ts":         action.get("ts", ""),
                "suspicious": susp,
            })

        # --- file_deleted ---
        for action in self._pat.get_actions_by_type(guid, "file_deleted"):
            deleted.append({
                "path":   action.get("path", ""),
                "sha256": action.get("sha256", ""),
                "ts":     action.get("ts", ""),
            })

        # --- file_timestomped ---
        for action in self._pat.get_actions_by_type(guid, "file_timestomped"):
            timestomped.append({
                "path":   action.get("path", ""),
                "sha256": action.get("sha256", ""),
                "ts":     action.get("ts", ""),
            })

        # --- wrote_ads (alternate data stream) ---
        for action in self._pat.get_actions_by_type(guid, "wrote_ads"):
            path = action.get("path", "")
            ads_written.append({
                "path":        path,
                "stream_name": action.get("stream_name", ""),
                "sha256":      action.get("sha256", ""),
                "ts":          action.get("ts", ""),
            })

        return {
            "guid":              guid,
            "total_file_events": len(created) + len(deleted) + len(timestomped) + len(ads_written),
            "created":           created,
            "deleted":           deleted,
            "timestomped":       timestomped,
            "ads_written":       ads_written,
            "suspicious_paths":  list(set(suspicious_paths)),
        }

    # ── TOOL 2: NETWORK ACTIVITY ──────────────────────────────────────────────

    def get_network_activity(self, guid: str) -> Dict[str, Any]:
        """
        Query the PAT for all network activity by a given process.

        Covers: network_connection, dns_query.

        Each connection is annotated with `external` = True when the destination
        IP is NOT a private RFC-1918 / loopback address — these are potential
        C2 or exfiltration endpoints.

        Parameters
        ----------
        guid : ProcessInstance GUID string.

        Returns
        -------
        {
          "guid": str,
          "connections": [{
              "dst_ip": str, "dst_port": str, "dst_host": str,
              "src_ip": str, "src_port": str,
              "protocol": str, "initiated": str,
              "ts": str, "external": bool
          }],
          "dns_queries": [{"query": str, "results": str, "status": str, "ts": str}],
          "external_ips":     [str],   # unique external IPs contacted
          "external_domains": [str],   # unique external domains queried
          "total_connections": int,
          "total_dns_queries": int,
        }
        """
        connections      = []
        dns_queries      = []
        external_ips     = set()
        external_domains = set()

        # --- network_connection ---
        for action in self._pat.get_actions_by_type(guid, "network_connection"):
            dst_ip = action.get("dst_ip", "")
            ext    = _is_external_ip(dst_ip) if dst_ip else False
            if ext and dst_ip:
                external_ips.add(dst_ip)
            connections.append({
                "dst_ip":   dst_ip,
                "dst_port": action.get("dst_port", ""),
                "dst_host": action.get("dst_host", ""),
                "src_ip":   action.get("src_ip", ""),
                "src_port": action.get("src_port", ""),
                "protocol": action.get("protocol", ""),
                "initiated":action.get("initiated", ""),
                "ts":       action.get("ts", ""),
                "external": ext,
            })

        # --- dns_query ---
        for action in self._pat.get_actions_by_type(guid, "dns_query"):
            query = action.get("query", "")
            dns_queries.append({
                "query":   query,
                "results": action.get("results", ""),
                "status":  action.get("status", ""),
                "ts":      action.get("ts", ""),
            })
            # treat all queried external domains as potential C2 indicators
            if query and not query.endswith((".local", ".internal", ".corp")):
                external_domains.add(query)

        return {
            "guid":              guid,
            "connections":       connections,
            "dns_queries":       dns_queries,
            "external_ips":      sorted(external_ips),
            "external_domains":  sorted(external_domains),
            "total_connections": len(connections),
            "total_dns_queries": len(dns_queries),
        }

    # ── TOOL 3: REGISTRY CHANGES ──────────────────────────────────────────────

    def get_registry_changes(self, guid: str) -> Dict[str, Any]:
        """
        Query the PAT for all registry write activity by a given process.

        Covers: registry_write (event types: add, set, rename — Sysmon 12/13/14).

        Each entry is annotated with `suspicious` when the registry key matches
        a known persistence pattern (Run keys, Winlogon, Services, AppInit, etc.).

        Parameters
        ----------
        guid : ProcessInstance GUID string.

        Returns
        -------
        {
          "guid": str,
          "total_registry_writes": int,
          "writes": [{
              "reg_type": str,   # "add" | "set" | "rename"
              "key": str,
              "details": str,
              "new_name": str,
              "ts": str,
              "suspicious": bool,
          }],
          "suspicious_keys": [str],   # deduplicated list of flagged keys
        }
        """
        writes         = []
        suspicious_keys = []

        for action in self._pat.get_actions_by_type(guid, "registry_write"):
            key  = action.get("key", "")
            susp = _is_suspicious_reg_key(key)
            if susp:
                suspicious_keys.append(key)
            writes.append({
                "reg_type":  action.get("reg_type", ""),
                "key":       key,
                "details":   action.get("details", ""),
                "new_name":  action.get("new_name", ""),
                "ts":        action.get("ts", ""),
                "suspicious": susp,
            })

        return {
            "guid":                  guid,
            "total_registry_writes": len(writes),
            "writes":                writes,
            "suspicious_keys":       list(set(suspicious_keys)),
        }

    # ── TOOL 4: PROCESS IDENTITY ──────────────────────────────────────────────

    def get_process_identity(self, guid: str) -> Dict[str, Any]:
        """
        Return the static identity record for a process from the PAT.

        Useful when the LLM needs to verify trust signals (signed, integrity
        level, image path) for a process it encountered in the lineage or blast
        radius that it hasn't yet examined.

        Parameters
        ----------
        guid : ProcessInstance GUID string.

        Returns
        -------
        The identity hash dict from Redis, or {"error": "not found"} if absent.
        Fields: guid, image, image_path, parent_guid, parent_image, cmdline,
                user, pid, host_id, start_time, end_time, alive,
                integrity_level, signature, signed.
        """
        identity = self._pat.get_identity(guid)
        if identity is None:
            return {"error": f"No PAT identity record for guid={guid!r}"}
        return dict(identity)

    # ── TOOL 5: INJECTION CHAINS ──────────────────────────────────────────────

    def get_injection_chains(self, guid: str) -> Dict[str, Any]:
        """
        Return all remote-thread injections performed by (or received by) a process.

        This answers: "Did process-A inject into any other process, creating a
        hidden execution context (backdoor)?"

        Covers: injected_thread_into, received_injected_thread.

        Parameters
        ----------
        guid : ProcessInstance GUID string.

        Returns
        -------
        {
          "guid": str,
          "injected_into": [{
              "target_guid": str, "target_image": str,
              "start_address": str, "start_module": str,
              "start_function": str, "ts": str
          }],
          "received_from": [{
              "source_guid": str, "source_image": str,
              "start_address": str, "start_function": str, "ts": str
          }],
          "total_injections_out": int,
          "total_injections_in":  int,
        }
        """
        injected_into = []
        received_from = []

        for action in self._pat.get_actions_by_type(guid, "injected_thread_into"):
            injected_into.append({
                "target_guid":     action.get("target_guid", ""),
                "target_image":    action.get("target_image", ""),
                "start_address":   action.get("start_address", ""),
                "start_module":    action.get("start_module", ""),
                "start_function":  action.get("start_function", ""),
                "ts":              action.get("ts", ""),
            })

        for action in self._pat.get_actions_by_type(guid, "received_injected_thread"):
            received_from.append({
                "source_guid":    action.get("source_guid", ""),
                "source_image":   action.get("source_image", ""),
                "start_address":  action.get("start_address", ""),
                "start_function": action.get("start_function", ""),
                "ts":             action.get("ts", ""),
            })

        return {
            "guid":                  guid,
            "injected_into":         injected_into,
            "received_from":         received_from,
            "total_injections_out":  len(injected_into),
            "total_injections_in":   len(received_from),
        }

    # ── TOOL 6: LOADED DRIVERS ────────────────────────────────────────────────

    def get_loaded_drivers(self, guid: str) -> Dict[str, Any]:
        """
        Return all kernel drivers and DLLs loaded by a process.

        Unsigned drivers or drivers loaded from unusual paths are a strong
        indicator of rootkit installation.

        Covers: driver_loaded, image_loaded (DLL).

        Parameters
        ----------
        guid : ProcessInstance GUID string.

        Returns
        -------
        {
          "guid": str,
          "drivers": [{
              "image_loaded": str, "sha256": str,
              "signed": str, "signature": str, "ts": str,
              "suspicious": bool   # True when unsigned or path is unusual
          }],
          "dlls": [{
              "image_loaded": str, "sha256": str,
              "signed": str, "signature": str, "ts": str
          }],
          "unsigned_drivers": [str],
        }
        """
        drivers         = []
        dlls            = []
        unsigned_drivers = []

        # --- driver_loaded (Sysmon event 6) ---
        for action in self._pat.get_actions_by_type(guid, "driver_loaded"):
            img    = action.get("image_loaded", "")
            signed = action.get("signed", "")
            susp   = (signed.lower() == "false") or _is_suspicious_path(img)
            if susp:
                unsigned_drivers.append(img)
            drivers.append({
                "image_loaded": img,
                "sha256":       action.get("sha256", ""),
                "signed":       signed,
                "signature":    action.get("signature", ""),
                "ts":           action.get("ts", ""),
                "suspicious":   susp,
            })

        # --- image_loaded / DLL (Sysmon event 7) ---
        for action in self._pat.get_actions_by_type(guid, "image_loaded"):
            dlls.append({
                "image_loaded": action.get("image_loaded", ""),
                "sha256":       action.get("sha256", ""),
                "signed":       action.get("signed", ""),
                "signature":    action.get("signature", ""),
                "ts":           action.get("ts", ""),
            })

        return {
            "guid":             guid,
            "drivers":          drivers,
            "dlls":             dlls,
            "unsigned_drivers": list(set(unsigned_drivers)),
        }

    # ── TOOL 7: PROCESS TAMPERING ──────────────────────────────────────────────

    def get_process_tampering(self, guid: str) -> Dict[str, Any]:
        """
        Return all process-tampering events involving a process (Sysmon event 25).

        Covers hollowing and herpadering: tampered_process, was_tampered_by.

        Parameters
        ----------
        guid : ProcessInstance GUID string.

        Returns
        -------
        {
          "guid": str,
          "tampered_others": [{"target_guid": str, "target_image": str, "tamper_type": str, "ts": str}],
          "was_tampered_by": [{"source_guid": str, "source_image": str, "tamper_type": str, "ts": str}],
        }
        """
        tampered_others = []
        was_tampered    = []

        for action in self._pat.get_actions_by_type(guid, "tampered_process"):
            tampered_others.append({
                "target_guid":  action.get("target_guid", ""),
                "target_image": action.get("target_image", ""),
                "tamper_type":  action.get("tamper_type", ""),
                "ts":           action.get("ts", ""),
            })

        for action in self._pat.get_actions_by_type(guid, "was_tampered_by"):
            was_tampered.append({
                "source_guid":  action.get("source_guid", ""),
                "source_image": action.get("source_image", ""),
                "tamper_type":  action.get("tamper_type", ""),
                "ts":           action.get("ts", ""),
            })

        return {
            "guid":            guid,
            "tampered_others": tampered_others,
            "was_tampered_by": was_tampered,
        }

    # ── TOOL 8: CHILD PROCESSES ───────────────────────────────────────────────

    def get_child_processes(self, guid: str) -> Dict[str, Any]:
        """
        Return the direct children spawned by a process, with their identity
        pulled from the PAT.

        Useful for tracing lateral movement: "Did process-A spawn any
        interpreters, net commands, or unusual binaries?"

        Parameters
        ----------
        guid : ProcessInstance GUID string.

        Returns
        -------
        {
          "guid": str,
          "children": [{
              "child_guid": str, "child_image": str,
              "child_cmdline": str, "ts": str,
              "identity": dict | None    # full PAT identity if available
          }],
          "total_children": int,
        }
        """
        children = []

        for action in self._pat.get_actions_by_type(guid, "child_spawned"):
            child_guid  = action.get("child_guid", "")
            child_image = action.get("child_image", "")
            identity    = self._pat.get_identity(child_guid) if child_guid else None
            children.append({
                "child_guid":    child_guid,
                "child_image":   child_image,
                "child_cmdline": action.get("child_cmdline", ""),
                "ts":            action.get("ts", ""),
                "identity":      dict(identity) if identity else None,
            })

        return {
            "guid":           guid,
            "children":       children,
            "total_children": len(children),
        }


# ══════════════════════════════════════════════════════════════════════════════
# GEMINI FUNCTION DECLARATIONS
# ══════════════════════════════════════════════════════════════════════════════

def get_tool_declarations() -> list:
    """
    Return a list of Gemini FunctionDeclaration objects for all registered tools.

    Passed directly to GenerativeModel(tools=[...]) so Gemini knows what it
    can call and what arguments each function expects.
    """
    import google.generativeai as genai
    from google.generativeai import protos

    # Helper: build a simple single-string-arg function declaration
    def _guid_tool(name: str, description: str) -> genai.protos.Tool:
        return genai.protos.Tool(
            function_declarations=[
                genai.protos.FunctionDeclaration(
                    name=name,
                    description=description,
                    parameters=genai.protos.Schema(
                        type=genai.protos.Type.OBJECT,
                        properties={
                            "guid": genai.protos.Schema(
                                type=genai.protos.Type.STRING,
                                description="ProcessInstance GUID string from the incident context.",
                            )
                        },
                        required=["guid"],
                    ),
                )
            ]
        )

    return [
        _guid_tool(
            "get_file_activity",
            "Get all file-system activity (create/delete/timestomp/ADS) for a process. "
            "Use this to find dropped malware, staged exfil files, or persistence droppers.",
        ),
        _guid_tool(
            "get_network_activity",
            "Get all network connections and DNS queries made by a process. "
            "Use this to identify C2 beaconing, data exfiltration endpoints, or lateral movement.",
        ),
        _guid_tool(
            "get_registry_changes",
            "Get all registry writes by a process. "
            "Use this to find persistence mechanisms (Run keys, Winlogon, services, AppInit).",
        ),
        _guid_tool(
            "get_process_identity",
            "Get the static identity record for a process (image path, cmdline, user, trust signals). "
            "Use this to verify signing status or check if an image runs from a suspicious location.",
        ),
        _guid_tool(
            "get_injection_chains",
            "Get all remote-thread injections performed by or received by a process. "
            "Use this to find hidden code execution contexts and backdoored processes.",
        ),
        _guid_tool(
            "get_loaded_drivers",
            "Get all kernel drivers and DLLs loaded by a process. "
            "Use this to detect rootkit installation or DLL hijacking.",
        ),
        _guid_tool(
            "get_process_tampering",
            "Get all process-hollowing or herpadering events involving a process. "
            "Use this to find impersonation or execution-within-legitimate-process techniques.",
        ),
        _guid_tool(
            "get_child_processes",
            "Get all child processes spawned by a process, with their identity. "
            "Use this to trace command execution, interpreter abuse, or lateral movement.",
        ),
    ]
