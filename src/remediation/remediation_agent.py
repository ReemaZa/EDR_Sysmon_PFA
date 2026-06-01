"""
remediation_agent.py  —  LLM Forensic Sweep Agent (ReAct loop over PAT tools).

PURPOSE
-------
The RemediationAgent is a COMPLETELY SEPARATE agent from the AnalystAgent.

  AnalystAgent    → real-time triage on a live Memgraph subgraph.
                    Goal: "Is this malicious? Kill it NOW."

  RemediationAgent → post-containment forensic sweep using the PAT.
                     Goal: "What did the attacker leave behind?
                            Is any persistence still active?
                            Was data stolen? Any backdoors?"
                     Output: findings (with confidence scores), cleanup
                             actions (with confidence scores), IOC list,
                             narrative.

REACT LOOP
----------
Iterates up to MAX_TOOL_ROUNDS rounds. Each round:
  - LLM calls a tool  → we execute it, log args + full result, continue.
  - LLM produces text → we force a final structured-output call.
After MAX_TOOL_ROUNDS the loop is broken and the final call is forced.

CHANGES vs previous version
----------------------------
1. Confidence scoring added throughout:
     - RemediationFinding schema now includes `confidence` (float 0.0–1.0)
       and `confidence_reason` (str).
     - cleanup_actions schema now includes `confidence` (float 0.0–1.0)
       and `confidence_reason` (str).
     - _get_final_report_schema() updated accordingly.
     - _parse() updated to propagate confidence fields into RemediationFinding
       dataclasses.
     - System prompt updated with confidence scoring guidance.

2. Initial message updated:
     - Section 3 (Executed Actions) now shows REAL target values (file paths,
       IPs, domains) instead of always showing process GUIDs.  This is because
       ContextBuilder._build_executed_actions was fixed to pass correct values.
     - NEW Section 4a: Analyst-Actioned Files — lists every file the analyst
       already quarantined/deleted that is scoped to this incident.
     - NEW Section 4b: Analyst-Actioned Network/DNS — lists every IP/domain
       the analyst already blocked that is scoped to this incident.
     - Section 8 (Task) updated: instructs the LLM to call
       get_analyst_actioned_artifacts FIRST for each GUID, and to use
       find_processes_by_ioc for lateral-spread pivots.
     - Section 8 also reminds the LLM: for NEW files use quarantine_file,
       never delete_file; do NOT re-recommend already-actioned artifacts.

3. _force_final_report: no structural changes; benefits automatically from
   the updated schema.

LOGGING
-------
The RemediationLogger instance is passed in from the orchestrator so every
tool call, every prompt, and every LLM response goes into the same log file
as the rest of the pipeline — giving you a single file to open for debugging.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

import google.generativeai as genai
from dotenv import load_dotenv

from src.remediation.remediation_logger import RemediationLogger
from src.remediation.remediation_models import (
    RemediationFinding,
    RemediationReport,
)
from src.remediation.remediation_tools import RemediationToolRegistry, get_tool_declarations

load_dotenv()

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
if not GEMINI_API_KEY:
    raise EnvironmentError(
        "[RemediationAgent] GEMINI_API_KEY environment variable is not set."
    )

MODEL_NAME      = "gemini-3.1-flash-lite"
MAX_TOOL_ROUNDS = 8
TOOL_CALL_DELAY = 5.0  # seconds between tool calls to respect rate limits (15 req/min)

genai.configure(api_key=GEMINI_API_KEY)


# ══════════════════════════════════════════════════════════════════════════════
# FINAL REPORT SCHEMA  (enforced via Gemini structured output)
# ══════════════════════════════════════════════════════════════════════════════

def _get_final_report_schema():
    """
    Build the Gemini response schema for the final structured output call.
    Only used in the force-final call (no tools, schema-only mode).

    CHANGES: findings and cleanup_actions now include confidence (number)
    and confidence_reason (string).
    """
    from google.ai.generativelanguage import Schema, Type

    finding_schema = Schema(
        type=Type.OBJECT,
        properties={
            "category":          Schema(type=Type.STRING, enum=[
                "persistence", "exfiltration", "backdoor", "lateral_movement", "other"
            ]),
            "severity":          Schema(type=Type.STRING, enum=["critical", "high", "medium", "low"]),
            "guid":              Schema(type=Type.STRING),
            "description":       Schema(type=Type.STRING),
            "iocs":              Schema(type=Type.ARRAY, items=Schema(type=Type.STRING)),
            # NEW: confidence scoring
            "confidence":        Schema(type=Type.NUMBER),
            "confidence_reason": Schema(type=Type.STRING),
        },
        required=["category", "severity", "guid", "description", "iocs",
                  "confidence", "confidence_reason"],
    )

    cleanup_schema = Schema(
        type=Type.OBJECT,
        properties={
            "priority":          Schema(type=Type.INTEGER),
            "action_type":       Schema(type=Type.STRING, enum=[
                "quarantine_file",        # use this for ALL new file threats
                "remove_registry_key",
                "block_ip",
                "block_domain",
                "disable_service",
                "scan_process",
                "revoke_credential",
                "patch_vulnerability",
                "reimage_host",
                "alert_analyst",
                # delete_file is intentionally REMOVED — use quarantine_file
            ]),
            "target":            Schema(type=Type.STRING),
            "reason":            Schema(type=Type.STRING),
            # NEW: confidence scoring
            "confidence":        Schema(type=Type.NUMBER),
            "confidence_reason": Schema(type=Type.STRING),
        },
        required=["priority", "action_type", "target", "reason",
                  "confidence", "confidence_reason"],
    )

    return Schema(
        type=Type.OBJECT,
        properties={
            "findings":        Schema(type=Type.ARRAY, items=finding_schema),
            "cleanup_actions": Schema(type=Type.ARRAY, items=cleanup_schema),
            "ioc_list":        Schema(type=Type.ARRAY, items=Schema(type=Type.STRING)),
            "narrative":       Schema(type=Type.STRING),
        },
        required=["findings", "cleanup_actions", "ioc_list", "narrative"],
    )


# ══════════════════════════════════════════════════════════════════════════════
# SYSTEM PROMPT
# ══════════════════════════════════════════════════════════════════════════════

_SYSTEM_PROMPT = """
You are a senior forensic incident responder. Your role is POST-CONTAINMENT SWEEP.

The Analyst Agent has already triaged this incident and issued initial containment
actions (process kills, IP/domain blocks, file quarantines). Those actions are marked
as EXECUTED in your context. Your job is NOT to re-triage. It is to answer:

  1. PERSISTENCE  — Did the attacker plant any mechanisms that survive a reboot?
                    (Registry Run keys, startup files, scheduled tasks, services,
                     WMI subscriptions, DLL hijacking paths.)
                    Are they still ACTIVE?

     CRITICAL: For EVERY blast-radius GUID, call
                       get_persistence_mechanisms(guid) FIRST. This returns
                       exact removal commands you MUST recommend.
                       Examples:
                         - reg delete "HKEY_LOCAL_MACHINE\..." /v "ValueName" /f
                         - sc delete "ServiceName"
                         - schtasks /delete /tn "TaskName" /f
                    Use these EXACT commands in cleanup_actions.

  2. EXFILTRATION — Was data sent out? To which IPs/domains? Estimate what was stolen
                    (based on file activity before network connections).

  3. BACKDOORS    — Are any injected threads, hollowed processes, or rogue drivers
                    still resident in memory or on disk?

  4. CLEANUP      — Produce a prioritised, machine-executable cleanup action list.
                    Be specific: exact registry key to delete, exact file path to
                    quarantine, exact IP to block.

  5. IOC LIST     — Extract every artefact that could be used to hunt for this threat
                    on other hosts: file hashes, IPs, domains, registry keys, mutex names.

TOOL USAGE STRATEGY:
  - For EACH blast-radius GUID, call get_file_activity, get_network_activity,
    get_registry_changes, get_injection_chains, get_loaded_drivers,
    get_process_tampering.
  - Each result includes already_actioned_by_analyst flags inline — skip those.
  - Use get_analyst_actioned_artifacts only if you need a quick summary of what
    the analyst handled for a GUID before diving into details.  
  - For any suspicious IP, domain, or file hash you discover, call
    find_processes_by_ioc to detect lateral spread (other processes that
    touched the same IOC but were never flagged by the analyst).
  - If you find injections, call get_injection_chains on the source process.
  - If you find suspicious children, call get_child_processes then investigate each.
  - Be exhaustive: cover EVERY guid in blast_radius_guids.

FILE ACTION RULES (CRITICAL — follow exactly):
  - If get_file_activity or get_analyst_actioned_artifacts shows
    already_actioned_by_analyst=True for a file path → SKIP IT. Do not
    include it in cleanup_actions. Acknowledge it as already handled.
  - For any NEW suspicious file not already actioned → use quarantine_file.
    NEVER use delete_file. Quarantine is reversible; deletion is not.

NETWORK ACTION RULES (CRITICAL — follow exactly):
  - If get_network_activity or get_analyst_actioned_artifacts shows
    already_actioned_by_analyst=True for an IP or domain → SKIP IT.
    Do not recommend blocking it again.
  - For any NEW suspicious external IP or domain not already blocked → use block_ip
    or block_domain.

REGISTRY ACTION RULES (CRITICAL — follow exactly):
  - For ANY persistence-related registry key found via get_persistence_mechanisms()
    → use remove_registry_key with the EXACT full path.
  
  - For services → use remove_registry_key (do NOT use disable_service).
    Format: "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\{ServiceName}"
    Example: "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\malware_svc"
  
  - For scheduled tasks → use remove_registry_key (do NOT use disable_task or disable_service).
    Format: "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\{TaskName}"
    Example: "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\Roaming"
  
  - For Run keys / startup registry entries → use remove_registry_key with the full value path.
    Format: "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    (The LLM must specify the exact value name being deleted in the action reason.)
  
  - For startup files (in Startup folders) → use quarantine_file (not delete_file).

IMPORTANT EDGE CASES:
  - If a registry key is already_actioned_by_analyst=True → DO NOT recommend removing it again.
  - If a file is already_actioned_by_analyst=True → DO NOT recommend quarantining it again.
  - For scheduled tasks created via registry modifications, the task_name must match exactly
    what appears in the TaskCache\Tree\ registry path for schtasks /delete to work.
CONFIDENCE SCORING (required for every finding and every cleanup action):
  Assign a confidence score (0.0–1.0) based on the quality of corroborating evidence:
    1.0 — Multiple independent tool results confirm it
           (e.g. registry Run key found AND the file at that path exists AND
            network beacon to same IP confirmed)
    0.7 — Single clear, direct tool result
           (e.g. registry key confirmed by get_registry_changes alone)
    0.4 — Indirect or circumstantial evidence
           (e.g. file path matches persistence pattern but no registry key confirms it)
    0.2 — Heuristic / pattern match only
           (e.g. process image is in Temp folder but no suspicious action confirmed)
  Always provide confidence_reason: a short sentence explaining what evidence
  drove the score.

IMPORTANT:
  - Base every finding strictly on tool results. Never invent file paths, IPs, or keys.
  - If a tool returns empty results, note this as "no activity observed" and move on.
  - The narrative should read like a professional incident report.
  - Severity: critical = active threat still present; high = significant residual risk;
    medium = cleanup needed but no active threat; low = informational.
""".strip()


# ══════════════════════════════════════════════════════════════════════════════
# REMEDIATION AGENT
# ══════════════════════════════════════════════════════════════════════════════

class RemediationAgent:
    """
    Post-containment forensic sweep agent.

    One instance per incident group. Do NOT reuse across incidents.

    Usage
    -----
        agent  = RemediationAgent(tool_registry, logger)
        report = agent.run(context_payload, incident_id, root_guid)
    """

    def __init__(self, tool_registry: RemediationToolRegistry, logger: RemediationLogger):
        """
        Parameters
        ----------
        tool_registry : RemediationToolRegistry bound to the live PAT.
        logger        : shared RemediationLogger for this pipeline run.
        """
        self._registry   = tool_registry
        self._logger     = logger
        self._tool_decls = get_tool_declarations()

    # ── PUBLIC ENTRY POINT ────────────────────────────────────────────────────

    def run(
        self,
        context_payload: Dict[str, Any],
        incident_id:     str,
        root_guid:       str,
    ) -> RemediationReport:
        """
        Run the full ReAct forensic loop for one incident and return a report.

        Parameters
        ----------
        context_payload : JSON dict built by ContextBuilder.build_context().
        incident_id     : IncidentGroup.incident_id (used for report filename).
        root_guid       : IncidentGroup.root_guid (used for report metadata).

        Returns
        -------
        RemediationReport — always (falls back to empty report on total failure).
        """
        tool_call_log: List[Dict[str, Any]] = []
        raw_llm_final = ""

        try:
            # Build and log the full opening prompt
            initial_message = self._build_initial_message(context_payload)
            self._logger.prompt(initial_message)

            # Run the ReAct loop
            raw_report, tool_call_log = self._react_loop(
                initial_message=initial_message,
                incident_id=    incident_id,
            )
            raw_llm_final = json.dumps(raw_report)

            # Log the raw structured response the LLM produced
            self._logger.llm_response(raw_report)

        except Exception as exc:
            self._logger.error(
                f"RemediationAgent failed for incident={incident_id}", exc
            )
            raw_report = self._fallback_report()

        report = self._parse(
            raw=           raw_report,
            incident_id=   incident_id,
            root_guid=     root_guid,
            tool_call_log= tool_call_log,
            raw_llm_final= raw_llm_final,
        )

        self._save_report(report)
        return report

    # ── REACT LOOP ────────────────────────────────────────────────────────────

    def _react_loop(
        self,
        initial_message: str,
        incident_id:     str,
    ):
        """
        Drive the Gemini ReAct loop.

        Every round is logged:
          - Round number + timestamp (react_round_start)
          - Each tool called: name, args, full result (tool_call)
          - When LLM stops calling tools: partial text (react_no_tool_calls)
          - When max rounds hit: warning (react_max_rounds)
          - On clean exit: round count (react_done)

        Returns
        -------
        (raw_report_dict, tool_call_log)
        """
        model = genai.GenerativeModel(
            MODEL_NAME,
            system_instruction=_SYSTEM_PROMPT,
            tools=self._tool_decls,
        )

        chat           = model.start_chat(history=[])
        tool_call_log: List[Dict[str, Any]] = []
        rounds         = 0

        # First turn — send the full incident context
        response = chat.send_message(initial_message)

        while rounds < MAX_TOOL_ROUNDS:
            rounds += 1
            self._logger.react_round_start(rounds, MAX_TOOL_ROUNDS)

            candidate = response.candidates[0]

            # Collect any function calls in this response
            fn_calls = [
                part.function_call
                for part in candidate.content.parts
                if hasattr(part, "function_call") and part.function_call.name
            ]

            if not fn_calls:
                # LLM finished reasoning — extract any partial text and force final
                partial_text = "".join(
                    part.text
                    for part in candidate.content.parts
                    if hasattr(part, "text")
                )
                self._logger.react_no_tool_calls(rounds, partial_text)
                self._logger.react_done(rounds)

                raw = self._force_final_report(partial_text, incident_id)
                return raw, tool_call_log

            # Execute each tool call, log it, and build the response parts
            tool_response_parts = []
            for fn_call in fn_calls:
                tool_name = fn_call.name
                args      = dict(fn_call.args)

                result = self._registry.call(tool_name, args)

                # Log the full call + result into the remediation log file
                self._logger.tool_call(
                    round_=rounds,
                    name=  tool_name,
                    args=  args,
                    result=result,
                )

                tool_call_log.append({
                    "round":  rounds,
                    "tool":   tool_name,
                    "args":   args,
                    "result": result,
                })

                tool_response_parts.append(
                    genai.protos.Part(
                        function_response=genai.protos.FunctionResponse(
                            name=tool_name,
                            response={"result": json.dumps(result)},
                        )
                    )
                )

            # Rate limiting: wait before sending tool results back to respect API quotas
            # 15 requests/minute = 1 request per 4 seconds; we use 5s delay per tool call
            if len(tool_response_parts) > 0:
                self._logger.info(
                    f"Rate limit: waiting {TOOL_CALL_DELAY}s before sending tool results..."
                )
                time.sleep(TOOL_CALL_DELAY)

            # Send all tool results back in one turn
            response = chat.send_message(tool_response_parts)

        # Reached max rounds
        self._logger.react_max_rounds(MAX_TOOL_ROUNDS)
        partial_text = "".join(
            part.text
            for part in response.candidates[0].content.parts
            if hasattr(part, "text")
        )
        raw = self._force_final_report(partial_text, incident_id)
        return raw, tool_call_log

    # ── FORCE FINAL REPORT ────────────────────────────────────────────────────

    def _force_final_report(
        self,
        accumulated_reasoning: str,
        incident_id:           str,
    ) -> Dict[str, Any]:
        """
        Send one final schema-only call to Gemini to extract the structured report.

        Logs the force-final prompt and the structured response it returns.
        """
        force_model = genai.GenerativeModel(
            MODEL_NAME,
            system_instruction=_SYSTEM_PROMPT,
            # No tools — schema output only
        )

        force_prompt = (
            "Based on all the tool results and reasoning above, produce your final "
            "RemediationReport now. Be exhaustive — include every finding, every IOC, "
            "and every cleanup action you identified.\n\n"
            "Remember:\n"
            "  - Every finding MUST have a confidence (0.0–1.0) and confidence_reason.\n"
            "  - Every cleanup action MUST have a confidence (0.0–1.0) and confidence_reason.\n"
            "  - Do NOT include cleanup actions for artifacts already actioned by the analyst.\n"
            "  - Use quarantine_file for new file threats, never delete_file.\n\n"
            f"Your accumulated analysis:\n{accumulated_reasoning}"
        )

        # Log the force-final prompt separately so you can distinguish it
        # from the opening prompt in the log file
        self._logger.force_final_prompt(force_prompt)

        try:
            resp = force_model.generate_content(
                force_prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.05,
                    top_p=0.95,
                    max_output_tokens=4096,
                    response_mime_type="application/json",
                    response_schema=_get_final_report_schema(),
                ),
            )
            result = json.loads(resp.text)
            return result
        except Exception as exc:
            self._logger.error("Force-final structured call failed", exc)
            return self._fallback_report()

    # ── OPENING PROMPT BUILDER ────────────────────────────────────────────────

    def _build_initial_message(self, context_payload: Dict[str, Any]) -> str:
        """
        Serialise the ContextBuilder payload into the opening LLM message.
        
        OPTIMISED: Reduced message size to comply with rate limits.
        Sections:
          1 — Incident overview (condensed)
          2 — Process action summaries (condensed - notable actions already filtered)
          3 — Analyst-actioned artifacts (what NOT to re-recommend)
          4 — Task instructions
        """
        lines = []

        # ── Section 1: Overview ───────────────────────────────────────────────
        lines += [
            "═" * 80,
            "INCIDENT OVERVIEW",
            "═" * 80,
            f"  Incident ID : {context_payload.get('incident_id', '?')}",
            f"  Root GUID   : {context_payload.get('root_guid', '?')}",
            f"  Member GUIDs: {context_payload.get('member_guids', [])}",
            f"  Chain truncated (PAT predates monitoring): "
            f"{context_payload.get('chain_truncated', False)}",
            "",
        ]

        # ── Section 2: Process action summaries (CRITICAL forensic data) ──────
        lines += [
            "═" * 80,
            "PROCESS ACTION SUMMARIES (what each blast-radius process DID)",
            "═" * 80,
        ]
        for summary in context_payload.get("process_action_summaries", []):
            lines.append(
                f"  GUID={summary.get('guid')}  image={summary.get('image', '?')}"
            )
            counts = summary.get("action_counts", {})
            # Show top counts only
            top_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:5]
            for atype, cnt in top_counts:
                lines.append(f"    {atype}: {cnt} event(s)")
            notable = summary.get("notable_actions", [])
            if notable:
                lines.append(f"    NOTABLE (top {len(notable)} types):")
                for note in notable:
                    lines.append(
                        f"      [{note.get('type')}] "
                        f"{json.dumps({k: v for k, v in note.items() if k != 'type'})}"
                    )
            lines.append("")

        # ── Section 3: Analyst-actioned artifacts (what NOT to re-recommend) ──
        analyst_files = context_payload.get("analyst_file_actions", [])
        analyst_network = context_payload.get("analyst_network_actions", [])
        
        if analyst_files or analyst_network:
            lines += ["═" * 80, "ALREADY-ACTIONED BY ANALYST (do NOT re-recommend)", "═" * 80]
            if analyst_files:
                lines.append(f"  Files ({len(analyst_files)}):")
                for f in analyst_files[:10]:  # Limit to first 10
                    lines.append(
                        f"    [{f.get('action_type', '?')}] {f.get('path', '?')[:100]}"
                    )
                if len(analyst_files) > 10:
                    lines.append(f"    ... and {len(analyst_files) - 10} more files")
            if analyst_network:
                lines.append(f"  Network/DNS ({len(analyst_network)}):")
                for n in analyst_network[:10]:  # Limit to first 10
                    lines.append(
                        f"    [{n.get('action_type', '?')}] "
                        f"{n.get('ioc_type', '?')}={n.get('value', '?')}"
                    )
                if len(analyst_network) > 10:
                    lines.append(f"    ... and {len(analyst_network) - 10} more IOCs")
            lines.append("")

        # ── Section 4: Task (OPTIMISED) ───────────────────────────────────────
        blast_guids = [
            n.get("guid")
            for n in context_payload.get("lineage", {}).get("blast_radius", [])
            if n.get("guid")
        ]
        lines += [
            "═" * 80,
            "TASK & STRICT GROUNDING RULES",
            "═" * 80,
            f"Investigate EXACTLY {len(blast_guids)} process(es) for persistence, exfiltration, backdoors:",
            f"  VALID GUID LIST: {blast_guids}",
            "",
            "CRITICAL GROUNDING CONSTRAINTS:",
            "  - ALWAYS verify that a GUID exists in the 'VALID GUID LIST' before investigating it or suggesting actions.",
            "  - NEVER suggest remediation actions (e.g., quarantine, block) based on assumptions or hypotheses.",
            "  - Every single recommended action MUST directly reference a specific, verified IOC or artifact returned in the actual tool outputs.",
            "  - If a tool returns NO data or empty results, state 'No suspicious activity found' and take NO action for that step.",
            "  - Prohibitive Rule: Do NOT invent, guess, or assume the existence of IP addresses, file paths, hashes, domains, or GUIDs.",
            "",
            "For EACH valid guid from the list:",
            "  1. get_file_activity           — quarantine_file for NEW suspicious files",
            "  2. get_network_activity        — block_ip / block_domain for NEW IOCs",
            "  3. get_registry_changes          — persistence keys",
            "  4. get_injection_chains          — remote thread injections",
            "  5. get_loaded_drivers             — unsigned drivers",
            "  6. get_process_tampering          — process hollowing",
            "  7. get_child_processes            — suspicious children",
            "",
            "For ANY suspicious IOC found in the ACTUAL tool outputs:",
            "  → Call find_processes_by_ioc(ioc_value, ioc_type) to detect lateral spread",
            "",
            "CONFIDENCE SCORING (required):",
            "  1.0 = Multiple independent tool results confirm it",
            "  0.7 = Single clear tool result",
            "  0.4 = Indirect evidence (Must explain the limitation of the evidence)",
            "  0.2 = Heuristic / pattern match only",
            "",
            "FILE RULES: use quarantine_file (never delete_file); skip already-actioned",
            "NETWORK RULES: use block_ip/block_domain for NEW IOCs only; skip already-blocked",
            "",
            "When done, produce RemediationReport. Every action item in the report MUST include a 'Source Tool Output' citation proving the threat exists.",
        ]

        return "\n".join(lines)

    # ── PARSER ────────────────────────────────────────────────────────────────

    def _parse(
        self,
        raw:           Dict[str, Any],
        incident_id:   str,
        root_guid:     str,
        tool_call_log: List[Dict[str, Any]],
        raw_llm_final: str,
    ) -> RemediationReport:
        """Convert the raw LLM JSON dict into a typed RemediationReport."""
        findings = [
            RemediationFinding(
                category=          f.get("category",          "other"),
                severity=          f.get("severity",          "medium"),
                guid=              f.get("guid",              ""),
                description=       f.get("description",       ""),
                evidence=          f.get("evidence",          {}),
                iocs=              f.get("iocs",              []),
                confidence=        float(f.get("confidence",  0.5)),
                confidence_reason= f.get("confidence_reason", ""),
            )
            for f in raw.get("findings", [])
        ]

        ioc_set = set(raw.get("ioc_list", []))
        for finding in findings:
            ioc_set.update(finding.iocs)

        return RemediationReport(
            incident_id=     incident_id,
            root_guid=       root_guid,
            produced_at=     datetime.now(timezone.utc).isoformat(),
            findings=        findings,
            cleanup_actions= raw.get("cleanup_actions", []),
            ioc_list=        sorted(ioc_set),
            narrative=       raw.get("narrative", ""),
            tool_call_log=   tool_call_log,
            raw_llm_response=raw_llm_final,
        )

    # ── REPORT PERSISTENCE ────────────────────────────────────────────────────

    def _save_report(self, report: RemediationReport) -> None:
        """Save the final RemediationReport to remediation_reports/<incident_id>.json."""
        import dataclasses
        try:
            os.makedirs("remediation_reports", exist_ok=True)
            path = f"remediation_reports/{report.incident_id}.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(dataclasses.asdict(report), f, indent=2, default=str)
            self._logger.info(f"Report JSON saved → {path}")
        except Exception as exc:
            self._logger.error("Could not save report JSON", exc)

    # ── FALLBACK ──────────────────────────────────────────────────────────────

    @staticmethod
    def _fallback_report() -> Dict[str, Any]:
        """Safe empty dict returned when the LLM call completely fails."""
        return {
            "findings":        [],
            "cleanup_actions": [],
            "ioc_list":        [],
            "narrative":       "Remediation agent failed to produce a report.",
        }