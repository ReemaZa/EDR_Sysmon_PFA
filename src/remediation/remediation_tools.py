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
  • Did the analyst already quarantine a file this process dropped?   [NEW]
  • Did the analyst already block a network/DNS IOC from this process? [NEW]
  • Which OTHER processes (outside blast radius) also touched a given IOC? [NEW]

DESIGN NOTES
------------
- Every function is PURE with respect to the LLM: it takes a guid (str),
  returns a JSON-serialisable dict, and never raises (errors are returned
  as {"error": "..."} dicts so the LLM can continue reasoning).
- The PAT is the single data source — no Memgraph queries here.
- Persistence detection uses a keyword allowlist for common persistence paths
  and registry keys so the LLM gets a pre-filtered "suspicious" flag.
- analyst_actioned_files / analyst_actioned_network are injected at
  construction time by ContextBuilder so tools can annotate inline.

CHANGES vs previous version
----------------------------
1. RemediationToolRegistry.__init__ now accepts two new dicts:
     analyst_actioned_files   : {file_path_lower → action_type}
     analyst_actioned_network : {ip_or_domain_lower → action_type}
   These are built by ContextBuilder from the Memgraph File/Network/DNS
   node queries and injected here.  Every existing tool that touches
   files or network data annotates its results with
   `already_actioned_by_analyst` and `analyst_action` fields.

2. get_file_activity — each "created" record now includes:
     already_actioned_by_analyst : bool
     analyst_action              : str  ("file_quarantine" | "file_deletion" | "")

3. get_network_activity — each connection record now includes:
     already_actioned_by_analyst : bool
     analyst_action              : str  ("ip_block" | "")
   Each dns_query record now includes:
     already_actioned_by_analyst : bool
     analyst_action              : str  ("dns_block" | "")

4. Two new tools added:
     get_analyst_actioned_artifacts(guid)
         Returns all files/IPs/domains the analyst already actioned that
         are linked to this process.  The LLM should call this first to
         avoid re-recommending already-handled artifacts.

     find_processes_by_ioc(ioc_value, ioc_type)
         Reverse-index pivot via PAT: given a file path, IP, or domain,
         returns every process GUID that ever touched it — including
         processes OUTSIDE the current blast radius.  Lets the agent
         discover lateral spread the analyst never flagged.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

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
        registry = RemediationToolRegistry(
            pat,
            analyst_actioned_files={...},
            analyst_actioned_network={...},
        )
        result = registry.call("get_file_activity", {"guid": "..."})

    The RemediationAgent calls registry.call(tool_name, args_dict) inside
    its ReAct loop — it never calls tool functions directly.

    Parameters
    ----------
    pat                    : PATBuilder instance (already connected to Redis).
    analyst_actioned_files : dict mapping lowercase file path → action_type
                             for every File node the analyst stamped with
                             pending_action.  Built by ContextBuilder.
    analyst_actioned_network: dict mapping lowercase ip or domain → action_type
                             for every Network/DNS node the analyst stamped.
                             Built by ContextBuilder.
    """

    def __init__(
        self,
        pat,
        analyst_actioned_files:   Optional[Dict[str, str]] = None,
        analyst_actioned_network: Optional[Dict[str, str]] = None,
    ):
        self._pat                    = pat
        # Normalise to lowercase for case-insensitive lookups
        self._analyst_files:   Dict[str, str] = {
            k.lower(): v for k, v in (analyst_actioned_files or {}).items()
        }
        self._analyst_network: Dict[str, str] = {
            k.lower(): v for k, v in (analyst_actioned_network or {}).items()
        }

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
            "get_file_activity":             self.get_file_activity,
            "get_network_activity":          self.get_network_activity,
            "get_registry_changes":          self.get_registry_changes,
            "get_process_identity":          self.get_process_identity,
            "get_injection_chains":          self.get_injection_chains,
            "get_loaded_drivers":            self.get_loaded_drivers,
            "get_process_tampering":         self.get_process_tampering,
            "get_child_processes":           self.get_child_processes,
            # NEW tools
            "get_analyst_actioned_artifacts": self.get_analyst_actioned_artifacts,
            "find_processes_by_ioc":          self.find_processes_by_ioc,
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

        Each record is annotated with:
          - `suspicious`                   : path matches a known persistence location.
          - `already_actioned_by_analyst`  : True if the analyst stamped this file
                                             with a pending_action in Memgraph.
          - `analyst_action`               : the action type the analyst chose
                                             ("file_quarantine" | "file_deletion" | "").

        IMPORTANT FOR THE LLM
        ---------------------
        If `already_actioned_by_analyst` is True, do NOT recommend any cleanup
        action for this file — acknowledge it as already handled by the analyst.
        For files where it is False, recommend `quarantine_file` (not delete).

        Parameters
        ----------
        guid : ProcessInstance GUID string.

        Returns
        -------
        {
          "guid": str,
          "total_file_events": int,
          "created":     [{"path", "sha256", "ts", "suspicious",
                           "already_actioned_by_analyst", "analyst_action"}],
          "deleted":     [{"path", "sha256", "ts"}],
          "timestomped": [{"path", "sha256", "ts"}],
          "ads_written": [{"path", "stream_name", "sha256", "ts"}],
          "suspicious_paths": [str],
          "analyst_actioned_paths": [str],  # paths the analyst already handled
        }
        """
        created          = []
        deleted          = []
        timestomped      = []
        ads_written      = []
        suspicious_paths      = []
        analyst_actioned_paths = []

        # --- file_created ---
        for action in self._pat.get_actions_by_type(guid, "file_created"):
            path       = action.get("path", "")
            susp       = _is_suspicious_path(path)
            actioned   = path.lower() in self._analyst_files
            act_type   = self._analyst_files.get(path.lower(), "")
            if susp:
                suspicious_paths.append(path)
            if actioned:
                analyst_actioned_paths.append(path)
            created.append({
                "path":                       path,
                "sha256":                     action.get("sha256", ""),
                "ts":                         action.get("ts", ""),
                "suspicious":                 susp,
                "already_actioned_by_analyst": actioned,
                "analyst_action":             act_type,
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
            "guid":                   guid,
            "total_file_events":      len(created) + len(deleted) + len(timestomped) + len(ads_written),
            "created":                created,
            "deleted":                deleted,
            "timestomped":            timestomped,
            "ads_written":            ads_written,
            "suspicious_paths":       list(set(suspicious_paths)),
            "analyst_actioned_paths": list(set(analyst_actioned_paths)),
        }

    # ── TOOL 2: NETWORK ACTIVITY ──────────────────────────────────────────────

    def get_network_activity(self, guid: str) -> Dict[str, Any]:
        """
        Query the PAT for all network activity by a given process.

        Covers: network_connection, dns_query.

        Each connection is annotated with:
          - `external`                     : destination IP is not RFC-1918.
          - `already_actioned_by_analyst`  : True if the analyst issued an
                                             ip_block for this destination IP.
          - `analyst_action`               : "ip_block" or "".

        Each dns_query is annotated with:
          - `already_actioned_by_analyst`  : True if the analyst issued a
                                             dns_block for this domain.
          - `analyst_action`               : "dns_block" or "".

        IMPORTANT FOR THE LLM
        ---------------------
        If `already_actioned_by_analyst` is True for an IP or domain, do NOT
        recommend blocking it again — acknowledge it as already handled.

        Parameters
        ----------
        guid : ProcessInstance GUID string.

        Returns
        -------
        {
          "guid": str,
          "connections": [{"dst_ip", "dst_port", "dst_host", "src_ip",
                           "src_port", "protocol", "initiated", "ts",
                           "external", "already_actioned_by_analyst",
                           "analyst_action"}],
          "dns_queries": [{"query", "results", "status", "ts",
                           "already_actioned_by_analyst", "analyst_action"}],
          "external_ips":     [str],
          "external_domains": [str],
          "analyst_actioned_ips":     [str],
          "analyst_actioned_domains": [str],
          "total_connections": int,
          "total_dns_queries": int,
        }
        """
        connections               = []
        dns_queries               = []
        external_ips              = set()
        external_domains          = set()
        analyst_actioned_ips      = set()
        analyst_actioned_domains  = set()

        # --- network_connection ---
        for action in self._pat.get_actions_by_type(guid, "network_connection"):
            dst_ip   = action.get("dst_ip", "")
            ext      = _is_external_ip(dst_ip) if dst_ip else False
            actioned = dst_ip.lower() in self._analyst_network
            act_type = self._analyst_network.get(dst_ip.lower(), "")
            if ext and dst_ip:
                external_ips.add(dst_ip)
            if actioned and dst_ip:
                analyst_actioned_ips.add(dst_ip)
            connections.append({
                "dst_ip":                      dst_ip,
                "dst_port":                    action.get("dst_port", ""),
                "dst_host":                    action.get("dst_host", ""),
                "src_ip":                      action.get("src_ip", ""),
                "src_port":                    action.get("src_port", ""),
                "protocol":                    action.get("protocol", ""),
                "initiated":                   action.get("initiated", ""),
                "ts":                          action.get("ts", ""),
                "external":                    ext,
                "already_actioned_by_analyst": actioned,
                "analyst_action":              act_type,
            })

        # --- dns_query ---
        for action in self._pat.get_actions_by_type(guid, "dns_query"):
            query    = action.get("query", "")
            actioned = query.lower() in self._analyst_network
            act_type = self._analyst_network.get(query.lower(), "")
            if actioned and query:
                analyst_actioned_domains.add(query)
            dns_queries.append({
                "query":                       query,
                "results":                     action.get("results", ""),
                "status":                      action.get("status", ""),
                "ts":                          action.get("ts", ""),
                "already_actioned_by_analyst": actioned,
                "analyst_action":              act_type,
            })
            if query and not query.endswith((".local", ".internal", ".corp")):
                external_domains.add(query)

        return {
            "guid":                      guid,
            "connections":               connections,
            "dns_queries":               dns_queries,
            "external_ips":              sorted(external_ips),
            "external_domains":          sorted(external_domains),
            "analyst_actioned_ips":      sorted(analyst_actioned_ips),
            "analyst_actioned_domains":  sorted(analyst_actioned_domains),
            "total_connections":         len(connections),
            "total_dns_queries":         len(dns_queries),
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
          "writes": [{"reg_type", "key", "details", "new_name", "ts",
                      "suspicious"}],
          "suspicious_keys": [str],
        }
        """
        writes          = []
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

        Parameters
        ----------
        guid : ProcessInstance GUID string.

        Returns
        -------
        {
          "guid": str,
          "injected_into": [{"target_guid", "target_image", "start_address",
                             "start_module", "start_function", "ts"}],
          "received_from": [{"source_guid", "source_image", "start_address",
                             "start_function", "ts"}],
          "total_injections_out": int,
          "total_injections_in":  int,
        }
        """
        injected_into = []
        received_from = []

        for action in self._pat.get_actions_by_type(guid, "injected_thread_into"):
            injected_into.append({
                "target_guid":    action.get("target_guid", ""),
                "target_image":   action.get("target_image", ""),
                "start_address":  action.get("start_address", ""),
                "start_module":   action.get("start_module", ""),
                "start_function": action.get("start_function", ""),
                "ts":             action.get("ts", ""),
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
            "guid":                 guid,
            "injected_into":        injected_into,
            "received_from":        received_from,
            "total_injections_out": len(injected_into),
            "total_injections_in":  len(received_from),
        }

    # ── TOOL 6: LOADED DRIVERS ────────────────────────────────────────────────

    def get_loaded_drivers(self, guid: str) -> Dict[str, Any]:
        """
        Return all kernel drivers and DLLs loaded by a process.

        Parameters
        ----------
        guid : ProcessInstance GUID string.

        Returns
        -------
        {
          "guid": str,
          "drivers": [{"image_loaded", "sha256", "signed", "signature",
                       "ts", "suspicious"}],
          "dlls": [{"image_loaded", "sha256", "signed", "signature", "ts"}],
          "unsigned_drivers": [str],
        }
        """
        drivers          = []
        dlls             = []
        unsigned_drivers = []

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
          "tampered_others": [{"target_guid", "target_image", "tamper_type", "ts"}],
          "was_tampered_by": [{"source_guid", "source_image", "tamper_type", "ts"}],
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

        Parameters
        ----------
        guid : ProcessInstance GUID string.

        Returns
        -------
        {
          "guid": str,
          "children": [{"child_guid", "child_image", "child_cmdline", "ts",
                        "identity": dict | None}],
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

    # ── TOOL 9 (NEW): ANALYST-ACTIONED ARTIFACTS ─────────────────────────────

    def get_analyst_actioned_artifacts(self, guid: str) -> Dict[str, Any]:
        """
        Return all files/IPs/domains linked to this process that the analyst
        already actioned.

        The LLM should call this early in the sweep for each blast-radius GUID
        to build an upfront picture of what has already been handled before
        recommending any new actions.

        How it works
        ------------
        Cross-references the process's PAT file + network events against
        the analyst_actioned_files and analyst_actioned_network dicts that
        were injected at registry construction time.

        Parameters
        ----------
        guid : ProcessInstance GUID string.

        Returns
        -------
        {
          "guid": str,
          "actioned_files": [{"path", "analyst_action"}],
          "actioned_ips":   [{"ip", "analyst_action"}],
          "actioned_domains": [{"domain", "analyst_action"}],
          "total": int,
          "note": str,   # reminder for the LLM about what NOT to re-recommend
        }
        """
        actioned_files   = []
        actioned_ips     = []
        actioned_domains = []

        # Check files created by this process
        for action in self._pat.get_actions_by_type(guid, "file_created"):
            path = action.get("path", "")
            if path.lower() in self._analyst_files:
                actioned_files.append({
                    "path":          path,
                    "analyst_action": self._analyst_files[path.lower()],
                })

        # Check network connections
        for action in self._pat.get_actions_by_type(guid, "network_connection"):
            ip = action.get("dst_ip", "")
            if ip.lower() in self._analyst_network:
                actioned_ips.append({
                    "ip":            ip,
                    "analyst_action": self._analyst_network[ip.lower()],
                })

        # Check DNS queries
        for action in self._pat.get_actions_by_type(guid, "dns_query"):
            domain = action.get("query", "")
            if domain.lower() in self._analyst_network:
                actioned_domains.append({
                    "domain":         domain,
                    "analyst_action": self._analyst_network[domain.lower()],
                })

        # Deduplicate
        seen_files = set()
        unique_files = []
        for item in actioned_files:
            if item["path"] not in seen_files:
                seen_files.add(item["path"])
                unique_files.append(item)

        seen_ips = set()
        unique_ips = []
        for item in actioned_ips:
            if item["ip"] not in seen_ips:
                seen_ips.add(item["ip"])
                unique_ips.append(item)

        seen_domains = set()
        unique_domains = []
        for item in actioned_domains:
            if item["domain"] not in seen_domains:
                seen_domains.add(item["domain"])
                unique_domains.append(item)

        total = len(unique_files) + len(unique_ips) + len(unique_domains)

        return {
            "guid":             guid,
            "actioned_files":   unique_files,
            "actioned_ips":     unique_ips,
            "actioned_domains": unique_domains,
            "total":            total,
            "note": (
                "These artifacts were already actioned by the AnalystAgent. "
                "Do NOT recommend any cleanup action for them. "
                "Acknowledge them as already handled in your findings."
            ),
        }

    # ── TOOL 10 (NEW): FIND PROCESSES BY IOC ─────────────────────────────────

    def find_processes_by_ioc(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        """
        Reverse-index pivot: given a file path, IP address, or domain, return
        every process GUID in the PAT that ever touched it.

        This is the key tool for lateral spread detection.  If a suspicious IP
        was contacted by a blast-radius process, call this to find ALL other
        processes on the host that also contacted it — they may be infected
        but were never flagged by the analyst's detection rules.

        Parameters
        ----------
        ioc_value : the artifact to pivot on.
                    For file  : absolute file path (e.g. "C:\\Temp\\evil.exe")
                    For ip    : IPv4/IPv6 address  (e.g. "1.2.3.4")
                    For domain: domain name        (e.g. "evil.com")
        ioc_type  : "file" | "ip" | "domain"

        Returns
        -------
        {
          "ioc_value":  str,
          "ioc_type":   str,
          "guids":      [str],   # all GUIDs that touched this IOC
          "total":      int,
          "identities": [dict],  # PAT identity record per GUID (image, user, etc.)
          "note": str,           # advisory for the LLM
        }
        """
        ioc_type = ioc_type.lower().strip()

        if ioc_type == "file":
            guids = self._pat.find_guids_by_file(ioc_value)
        elif ioc_type == "ip":
            guids = self._pat.find_guids_by_ip(ioc_value)
        elif ioc_type == "domain":
            guids = self._pat.find_guids_by_domain(ioc_value)
        else:
            return {
                "error": (
                    f"Unknown ioc_type={ioc_type!r}. "
                    "Must be one of: 'file', 'ip', 'domain'."
                )
            }

        identities = []
        for g in guids:
            ident = self._pat.get_identity(g)
            identities.append(dict(ident) if ident else {"guid": g, "error": "not found in PAT"})

        return {
            "ioc_value":  ioc_value,
            "ioc_type":   ioc_type,
            "guids":      list(guids),
            "total":      len(guids),
            "identities": identities,
            "note": (
                "Any GUID here that is NOT already in your blast_radius_guids "
                "may represent lateral spread or a co-infected process that the "
                "AnalystAgent did not flag. Investigate those GUIDs separately "
                "using get_process_identity and get_file_activity."
            ),
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
            "Results include 'already_actioned_by_analyst' flags — do NOT re-recommend "
            "any action for files where this flag is True. "
            "For new suspicious files, recommend quarantine_file (never delete_file).",
        ),
        _guid_tool(
            "get_network_activity",
            "Get all network connections and DNS queries made by a process. "
            "Results include 'already_actioned_by_analyst' flags for IPs and domains "
            "the analyst already blocked — do NOT recommend blocking those again.",
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
        # NEW TOOL 9
        _guid_tool(
            "get_analyst_actioned_artifacts",
            "Get all files, IPs, and domains linked to this process that the AnalystAgent "
            "already actioned (quarantined/blocked). Call this FIRST for each blast-radius "
            "GUID to know what is already handled before recommending new cleanup actions.",
        ),
        # NEW TOOL 10 — different signature (ioc_value + ioc_type)
        genai.protos.Tool(
            function_declarations=[
                genai.protos.FunctionDeclaration(
                    name="find_processes_by_ioc",
                    description=(
                        "Reverse-index pivot: given a suspicious file path, IP address, or domain, "
                        "find ALL process GUIDs in the PAT that ever touched it. "
                        "Use this after finding a suspicious IOC to detect lateral spread — "
                        "other processes that contacted the same C2 or dropped the same file "
                        "but were never flagged by the analyst."
                    ),
                    parameters=genai.protos.Schema(
                        type=genai.protos.Type.OBJECT,
                        properties={
                            "ioc_value": genai.protos.Schema(
                                type=genai.protos.Type.STRING,
                                description=(
                                    "The artifact to pivot on: "
                                    "absolute file path, IPv4/IPv6 address, or domain name."
                                ),
                            ),
                            "ioc_type": genai.protos.Schema(
                                type=genai.protos.Type.STRING,
                                enum=["file", "ip", "domain"],
                                description="Type of IOC: 'file', 'ip', or 'domain'.",
                            ),
                        },
                        required=["ioc_value", "ioc_type"],
                    ),
                )
            ]
        ),
    ]