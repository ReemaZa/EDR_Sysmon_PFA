# src/detection/l4_llm_detection/action_executor.py
"""
ActionExecutor  —  bridges AnalystAgent output → response_functions calls.

LLM ACTION SCHEMA (produced by AnalystAgent / analyst_agent.py):
─────────────────────────────────────────────────────────────────
  id           : str   — unique action identifier (e.g. "act-001")
  priority     : int   — execution order (lower = first)
  type         : str   — one of the action type literals (see ACTION TYPES below)
  target_type  : str   — "guid" | "tmpl" | "file" | "ip" | "domain" | "registry"
  target_value : str   — the identifier to act on (PID string, path, IP, domain, username…)
  reason       : str   — LLM explanation (logged, never executed)

ACTION TYPES → FUNCTION MAPPING:
─────────────────────────────────────────────────────────────────
  "process_termination"
      target_type  : "guid"
      target_value : process GUID string → resolved to PID via Memgraph
      calls        : response_functions.process_termination(pid: int, mode, force=True)

  "file_quarantine"
      target_type  : "file"
      target_value : absolute path to the suspicious file
      calls        : response_functions.file_quarantine(file_path: str, mode, quarantine_dir)

  "file_deletion"
      target_type  : "file"
      target_value : absolute path to the file to wipe
      calls        : response_functions.file_deletion(file_path: str, mode, secure_wipe, passes)

  "ip_block"
      target_type  : "ip"
      target_value : IPv4 or IPv6 address (e.g. "1.2.3.4")
      calls        : response_functions.ip_block(ip_address: str, mode, direction="both")

  "dns_block"
      target_type  : "domain"
      target_value : domain name (e.g. "evil.com")
      calls        : response_functions.dns_block(domain: str, mode, redirect_ip="0.0.0.0")

  "host_isolation"
      target_type  : (ignored — always acts on localhost)
      target_value : (ignored)
      calls        : response_functions.host_isolation(mode)

  "blacklist"
      target_type  : "ip" | "domain" | "file" (mapped to "hash") | "tmpl" (mapped to "process_name")
      target_value : the IOC value to persist
      calls        : response_functions.blacklist(identifier: str, blacklist_type, mode)
      note         : "file" target_type is stored as "hash"; "tmpl"/"guid" stored as "process_name"

  "identity_revocation"
      target_type  : (any — target_value is treated as username)
      target_value : Windows username string
      calls        : response_functions.identity_revocation(identity: str, mode)

  "patching"
      target_type  : (any — target_value is treated as asset/package identifier)
      target_value : package name or asset GUID
      calls        : response_functions.patching(target: str, mode, package_manager, packages)

  "shutdown"
      target_type  : (ignored — always acts on localhost)
      target_value : (ignored)
      calls        : response_functions.shutdown(mode, delay_seconds=30, force=False)

  "alert"
      target_type  : (any)
      target_value : identifier to attach to the alert (GUID, IP, path…)
      calls        : response_functions.alert(identifier, severity, message, mode)
      note         : severity is inferred from the action's priority field:
                       priority ≤ 1 → "critical", ≤ 3 → "high",
                       ≤ 6 → "medium", else → "low"

  "nothing"
      No function is called. The action is logged and silently skipped.
"""

from __future__ import annotations

import json
import threading
from typing import Any, Dict, List

# Import all response functions from the companion module.
# Adjust the import path to match your project layout.
from src.core import response as rf


class ActionExecutor:
    """
    Receives the list of action dicts produced by AnalystAgent and dispatches
    each one to the appropriate response_functions call.

    Execution model
    ───────────────
    execute_async() spawns a single daemon thread that runs actions in
    priority order (ascending).  Each action is dispatched independently;
    a failure in one action does not abort the remaining ones.

    Mode
    ────
    Pass mode="automatic" for fully automated containment (CI / high-confidence
    detections) or mode="approval" (default) to require operator confirmation
    before each destructive action.
    """

    def __init__(self, mode: rf.Mode = "approval"):
        """
        Parameters
        ----------
        mode : "automatic" | "approval"
            Default execution mode passed to every response_functions call.
            Individual dispatchers may override this for non-destructive actions
            (e.g. "alert" and "blacklist" always run in automatic mode).
        """
        self.mode = mode

    # ── PUBLIC API ────────────────────────────────────────────────────────────

    def execute_async(self, actions: List[Dict[str, Any]], anchor_guid: str) -> None:
        """
        Fire-and-forget execution of all actions in a daemon thread.

        Parameters
        ----------
        actions     : List of action dicts as produced by AnalystAgent.
        anchor_guid : GUID of the process that triggered this investigation.
                      Used only for logging / thread naming.
        """
        t = threading.Thread(
            target=self._run,
            args=(actions, anchor_guid),
            daemon=True,
            name=f"ActionExecutor-{anchor_guid[:8]}",
        )
        t.start()

    def execute_sync(self, actions: List[Dict[str, Any]], anchor_guid: str) -> List[Dict[str, Any]]:
        """
        Synchronous variant — blocks until all actions complete.
        Returns a list of result dicts (one per action) for callers that need
        to inspect outcomes (tests, orchestrators, etc.).

        Parameters
        ----------
        actions     : List of action dicts as produced by AnalystAgent.
        anchor_guid : GUID of the process that triggered this investigation.
        """
        return self._run(actions, anchor_guid)

    # ── INTERNAL RUNNER ───────────────────────────────────────────────────────

    def _run(self, actions: List[Dict[str, Any]], anchor_guid: str) -> List[Dict[str, Any]]:
        """Sort by priority then dispatch each action, collecting results."""
        sorted_actions = sorted(actions, key=lambda a: a.get("priority", 99))
        results = []
        for action in sorted_actions:
            action_id = action.get("id", "?")
            try:
                result = self._dispatch(action)
                results.append(result)
                print(
                    f"[ActionExecutor] {action_id} ({action.get('type')}) "
                    f"→ status={result.get('status')}"
                )
            except Exception as exc:
                err = {
                    "status": "error",
                    "action_id": action_id,
                    "type": action.get("type"),
                    "error": str(exc),
                }
                results.append(err)
                print(f"[ActionExecutor][ERROR] {action_id}: {exc}")
            # Persist execution record
        with open("action_log.jsonl", "a") as f:
            f.write(json.dumps({"anchor": anchor_guid, "actions": results}) + "\n")
        return results

    # ── DISPATCHER ────────────────────────────────────────────────────────────

    def _dispatch(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """
        Route a single action dict to the correct response_functions call.

        Parameters
        ----------
        action : Dict with keys: id, priority, type, target_type, target_value, reason
        """
        action_type  = action.get("type", "nothing")
        target_type  = action.get("target_type", "")
        target_value = action.get("target_value", "")
        priority     = action.get("priority", 9)
        reason       = action.get("reason", "")

        print(
            f"[ActionExecutor] Dispatching: {action_type} "
            f"target_type={target_type} target_value={target_value!r}"
        )

        match action_type:

            # ── process_termination ───────────────────────────────────────────
            # target_type  : "guid"
            # target_value : process GUID → resolved to integer PID via Memgraph
            case "process_termination":
                pid = self._guid_to_pid(target_value)
                if pid == 0:
                    return {
                        "status": "error",
                        "action": action_type,
                        "target": target_value,
                        "details": {"error": f"Could not resolve GUID {target_value!r} to a PID"},
                    }
                return rf.process_termination(pid=pid, mode=self.mode, force=True)

            # ── file_quarantine ───────────────────────────────────────────────
            # target_type  : "file"
            # target_value : absolute file path (str)
            case "file_quarantine":
                return rf.file_quarantine(file_path=target_value, mode=self.mode)

            # ── file_deletion ─────────────────────────────────────────────────
            # target_type  : "file"
            # target_value : absolute file path (str)
            case "file_deletion":
                return rf.file_deletion(
                    file_path=target_value,
                    mode=self.mode,
                    secure_wipe=True,
                    passes=3,
                )

            # ── ip_block ──────────────────────────────────────────────────────
            # target_type  : "ip"
            # target_value : IPv4 or IPv6 address string (e.g. "1.2.3.4")
            case "ip_block":
                return rf.ip_block(
                    ip_address=target_value,
                    mode=self.mode,
                    direction="both",
                )

            # ── dns_block ─────────────────────────────────────────────────────
            # target_type  : "domain"
            # target_value : domain name (e.g. "evil.com")
            case "dns_block":
                return rf.dns_block(
                    domain=target_value,
                    mode=self.mode,
                    redirect_ip="0.0.0.0",
                )

            # ── host_isolation ────────────────────────────────────────────────
            # target_type  : ignored (always acts on localhost)
            # target_value : ignored
            case "host_isolation":
                return rf.host_isolation(mode=self.mode)

            # ── blacklist ─────────────────────────────────────────────────────
            # target_type  : "ip" | "domain" | "file" → "hash" | "tmpl"/"guid" → "process_name"
            # target_value : the IOC value to persist
            # NOTE: always runs in automatic mode (non-destructive, write-only)
            case "blacklist":
                bl_type = self._map_blacklist_type(target_type)
                return rf.blacklist(
                    identifier=target_value,
                    blacklist_type=bl_type,
                    mode="automatic",
                )

            # ── identity_revocation ───────────────────────────────────────────
            # target_type  : (any — target_value is used directly as username)
            # target_value : Windows username string
            case "identity_revocation":
                return rf.identity_revocation(identity=target_value, mode=self.mode)

            # ── patching ──────────────────────────────────────────────────────
            # target_type  : (any — target_value treated as asset/package identifier)
            # target_value : package name or asset GUID
            case "patching":
                return rf.patching(
                    target=target_value,
                    mode=self.mode,
                    package_manager="choco",
                    packages=None,   # full system upgrade; override if needed
                )

            # ── shutdown ──────────────────────────────────────────────────────
            # target_type  : ignored (always acts on localhost)
            # target_value : ignored
            case "shutdown":
                return rf.shutdown(mode=self.mode, delay_seconds=30, force=False)

            # ── alert ─────────────────────────────────────────────────────────
            # target_type  : (any)
            # target_value : identifier attached to the alert (GUID, IP, path…)
            # severity is derived from the action's priority field:
            #   priority ≤ 1 → "critical" | ≤ 3 → "high" | ≤ 6 → "medium" | else → "low"
            # NOTE: always runs in automatic mode (fire-and-forget notification)
            case "alert":
                severity = self._priority_to_severity(priority)
                return rf.alert(
                    identifier=target_value,
                    severity=severity,
                    message=reason,
                    mode="automatic",
                )

            # ── nothing ───────────────────────────────────────────────────────
            # Explicit no-op declared by the LLM. Logged but not executed.
            case "nothing":
                print(f"[ActionExecutor] no-op for target={target_value!r}: {reason}")
                return {
                    "status": "skipped",
                    "action": "nothing",
                    "target": target_value,
                    "details": {"reason": reason},
                }

            case _:
                print(f"[ActionExecutor][WARN] Unknown action type: {action_type!r}")
                return {
                    "status": "error",
                    "action": action_type,
                    "target": target_value,
                    "details": {"error": f"Unknown action type: {action_type!r}"},
                }

    # ── HELPERS ───────────────────────────────────────────────────────────────

    @staticmethod
    def _guid_to_pid(guid: str) -> int:
        """
        Resolve a process GUID to an integer PID via Memgraph.

        Parameters
        ----------
        guid : ProcessInstance GUID string stored in the graph database.

        Returns
        -------
        int  : PID on success, 0 if not found or on DB error.
        """
        try:
            from gqlalchemy import Memgraph
            db   = Memgraph(host="localhost", port=7687)
            rows = list(db.execute_and_fetch(
                "MATCH (p:ProcessInstance {id: $guid}) RETURN p.pid AS pid",
                {"guid": guid},
            ))
            if rows and rows[0].get("pid"):
                return int(rows[0]["pid"])
            print(f"[ActionExecutor][WARN] No PID found for GUID {guid!r}")
            return 0
        except Exception as exc:
            print(f"[ActionExecutor][ERROR] Memgraph query failed for GUID {guid!r}: {exc}")
            return 0

    @staticmethod
    def _map_blacklist_type(target_type: str) -> str:
        """
        Map the LLM target_type to a blacklist_type accepted by response_functions.blacklist.

        LLM target_type → blacklist_type
        ──────────────────────────────────
        "ip"       → "ip"
        "domain"   → "domain"
        "hash"     → "hash"          (file paths stored by hash)
        "tmpl"     → "process_name"  (template = executable identity)
        "guid"     → "process_name"  (fall back to process_name)
        anything else → "process_name"

        Parameters
        ----------
        target_type : The target_type string from the LLM action dict.

        Returns
        -------
        str : One of "ip" | "domain" | "hash" | "process_name"
        """
        mapping = {
            "ip":       "ip",
            "domain":   "domain",
            "file":     "hash",
            "tmpl":     "process_name",
            "guid":     "process_name",
            "registry": "process_name",   # best-effort fallback
        }
        result = mapping.get(target_type, "process_name")
        if target_type not in mapping:
            print(
                f"[ActionExecutor][WARN] Unmapped blacklist target_type {target_type!r}, "
                f"defaulting to 'process_name'"
            )
        return result

    @staticmethod
    def _priority_to_severity(priority: int) -> str:
        """
        Derive an alert severity string from the LLM action priority field.

        Priority → Severity
        ────────────────────
        ≤ 1  → "critical"
        ≤ 3  → "high"
        ≤ 6  → "medium"
        else → "low"

        Parameters
        ----------
        priority : Integer priority from the LLM action dict (lower = more urgent).

        Returns
        -------
        str : One of "critical" | "high" | "medium" | "low"
        """
        if priority <= 1:
            return "critical"
        if priority <= 3:
            return "high"
        if priority <= 6:
            return "medium"
        return "low"