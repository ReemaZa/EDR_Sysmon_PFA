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

MODEL_NAME      = "gemini-3.1-flash-lite-preview"
MAX_TOOL_ROUNDS = 10

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
  - For EACH blast-radius GUID, call get_analyst_actioned_artifacts FIRST.
    This tells you what the analyst already handled — do NOT re-recommend those.
  - Then call get_file_activity, get_network_activity, get_registry_changes,
    get_injection_chains, get_loaded_drivers, get_process_tampering.
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

        Sections:
          1 — Incident overview
          2 — Analyst reasoning
          3 — Executed actions  (FIXED: real file paths / IPs / domains)
          4a — Analyst-actioned files (NEW)
          4b — Analyst-actioned network/DNS (NEW)
          5 — Process lineage
          6 — Process action summaries
          7 — Injection victims
          8 — Task instructions (UPDATED: new tool usage rules)
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

        # ── Section 2: Analyst reasoning ─────────────────────────────────────
        lines += ["═" * 80, "ANALYST AGENT REASONING", "═" * 80]
        for entry in context_payload.get("analyst_reasoning", []):
            lines += [
                f"  GUID={entry.get('guid')}  action={entry.get('pending_action')}",
                f"  reason: {entry.get('action_reason', 'N/A')}",
                f"  stamped_at: {entry.get('action_stamped_at', 'N/A')}",
                "",
            ]

        # ── Section 3: Executed actions (FIXED target_values) ─────────────────
        lines += ["═" * 80, "EXECUTED ACTIONS (containment already performed)", "═" * 80]
        for act in context_payload.get("executed_actions", []):
            lines.append(
                f"  [{act.get('status', '?')}] {act.get('action')} "
                f"→ {act.get('target_type')}={act.get('target_value')}  "
                f"at={act.get('executed_at', '?')}"
            )
        lines.append("")

        # ── Section 4a: Analyst-actioned files (NEW) ──────────────────────────
        analyst_files = context_payload.get("analyst_file_actions", [])
        lines += ["═" * 80, "ANALYST-ACTIONED FILES (already quarantined/deleted)", "═" * 80]
        if analyst_files:
            lines.append(
                "  These files have ALREADY been actioned by the AnalystAgent. "
                "Do NOT recommend any cleanup action for them."
            )
            for f in analyst_files:
                lines.append(
                    f"  [{f.get('action_type', '?')}]  path={f.get('path', '?')}  "
                    f"reason={f.get('action_reason', 'N/A')}"
                )
        else:
            lines.append("  (none — analyst did not action any files for this incident)")
        lines.append("")

        # ── Section 4b: Analyst-actioned network/DNS (NEW) ───────────────────
        analyst_network = context_payload.get("analyst_network_actions", [])
        lines += ["═" * 80, "ANALYST-ACTIONED NETWORK/DNS (already blocked)", "═" * 80]
        if analyst_network:
            lines.append(
                "  These IPs/domains have ALREADY been blocked by the AnalystAgent. "
                "Do NOT recommend blocking them again."
            )
            for n in analyst_network:
                lines.append(
                    f"  [{n.get('action_type', '?')}]  {n.get('ioc_type', '?')}="
                    f"{n.get('value', '?')}  "
                    f"reason={n.get('action_reason', 'N/A')}"
                )
        else:
            lines.append("  (none — analyst did not block any IPs/domains for this incident)")
        lines.append("")

        # ── Section 5: Process lineage ────────────────────────────────────────
        lines += ["═" * 80, "PROCESS LINEAGE", "═" * 80]
        lines.append("  ANCESTRY CHAIN (root → flagged node):")
        for node in context_payload.get("lineage", {}).get("ancestry_chain", []):
            lines.append(
                f"    {node.get('image', '?')} "
                f"[pid={node.get('pid', '?')} alive={node.get('alive', '?')} "
                f"signed={node.get('signed', '?')} il={node.get('integrity_level', '?')}]"
                f"  GUID={node.get('guid', '?')}"
            )
            if node.get("cmdline"):
                lines.append(f"      cmdline: {node['cmdline'][:200]}")
        lines.append("")
        lines.append("  BLAST RADIUS (sweep targets):")
        for node in context_payload.get("lineage", {}).get("blast_radius", []):
            lines.append(
                f"    {node.get('image', '?')} "
                f"[pid={node.get('pid', '?')} alive={node.get('alive', '?')}]"
                f"  GUID={node.get('guid', '?')}"
            )
        lines.append("")

        # ── Section 6: Process action summaries ───────────────────────────────
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
            for atype, cnt in counts.items():
                lines.append(f"    {atype}: {cnt} event(s)")
            notable = summary.get("notable_actions", [])
            if notable:
                lines.append("    NOTABLE (first occurrence of each type):")
                for note in notable:
                    lines.append(
                        f"      [{note.get('type')}] "
                        f"{json.dumps({k: v for k, v in note.items() if k != 'type'})}"
                    )
            lines.append("")

        # ── Section 7: Injection victims ──────────────────────────────────────
        if context_payload.get("injection_victims"):
            lines += ["═" * 80, "INJECTION VICTIMS (scan — do NOT kill)", "═" * 80]
            for vic in context_payload["injection_victims"]:
                lines.append(
                    f"  GUID={vic.get('guid')}  image={vic.get('image', '?')} "
                    f"injected_by={vic.get('injected_by', '?')} "
                    f"signed={vic.get('signed', '?')}"
                )
            lines.append("")

        # ── Section 8: Task (UPDATED) ─────────────────────────────────────────
        blast_guids = [
            n.get("guid")
            for n in context_payload.get("lineage", {}).get("blast_radius", [])
            if n.get("guid")
        ]
        lines += [
            "═" * 80,
            "TASK",
            "═" * 80,
            f"Investigate the following {len(blast_guids)} GUID(s) using the available tools:",
            f"  {blast_guids}",
            "",
            "For EACH guid, in this order:",
            "  0. get_analyst_actioned_artifacts — call THIS FIRST to see what the analyst",
            "     already handled. Skip those artifacts in your cleanup_actions.",
            "  1. get_file_activity      — dropped files / persistence droppers.",
            "     → For files with already_actioned_by_analyst=True: acknowledge, skip.",
            "     → For NEW suspicious files: recommend quarantine_file (NOT delete_file).",
            "  2. get_network_activity   — C2 / exfil endpoints.",
            "     → For IPs/domains with already_actioned_by_analyst=True: acknowledge, skip.",
            "     → For NEW suspicious IPs/domains: recommend block_ip / block_domain.",
            "  3. get_registry_changes   — persistence keys.",
            "  4. get_injection_chains   — remote thread injections.",
            "  5. get_loaded_drivers     — unsigned kernel drivers.",
            "  6. get_process_tampering  — hollowing / herpadering.",
            "  7. get_child_processes    — suspicious children.",
            "",
            "For ANY suspicious file path, IP, or domain you find:",
            "  → Call find_processes_by_ioc(ioc_value, ioc_type) to detect lateral spread.",
            "  → Any returned GUID not in your blast_radius_guids may be a co-infected",
            "     process — investigate it with get_process_identity.",
            "",
            "Confidence scoring (REQUIRED for every finding and cleanup action):",
            "  1.0 — Multiple independent tool results confirm the finding.",
            "  0.7 — Single clear, direct tool result.",
            "  0.4 — Indirect / circumstantial evidence.",
            "  0.2 — Heuristic / pattern match only.",
            "",
            "When done, produce your final RemediationReport.",
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