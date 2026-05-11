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
                     Output: findings, cleanup actions, IOC list, narrative.

REACT LOOP
----------
Iterates up to MAX_TOOL_ROUNDS rounds. Each round:
  - LLM calls a tool  → we execute it, log args + full result, continue.
  - LLM produces text → we force a final structured-output call.
After MAX_TOOL_ROUNDS the loop is broken and the final call is forced.

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

MODEL_NAME     = "gemini-3.1-flash-lite-preview"
MAX_TOOL_ROUNDS = 10

genai.configure(api_key=GEMINI_API_KEY)


# ══════════════════════════════════════════════════════════════════════════════
# FINAL REPORT SCHEMA  (enforced via Gemini structured output)
# ══════════════════════════════════════════════════════════════════════════════

def _get_final_report_schema():
    """
    Build the Gemini response schema for the final structured output call.
    Only used in the force-final call (no tools, schema-only mode).
    """
    from google.ai.generativelanguage import Schema, Type

    finding_schema = Schema(
        type=Type.OBJECT,
        properties={
            "category":    Schema(type=Type.STRING, enum=[
                "persistence", "exfiltration", "backdoor", "lateral_movement", "other"
            ]),
            "severity":    Schema(type=Type.STRING, enum=["critical", "high", "medium", "low"]),
            "guid":        Schema(type=Type.STRING),
            "description": Schema(type=Type.STRING),
            "iocs":        Schema(type=Type.ARRAY, items=Schema(type=Type.STRING)),
        },
        required=["category", "severity", "guid", "description", "iocs"],
    )

    cleanup_schema = Schema(
        type=Type.OBJECT,
        properties={
            "priority":    Schema(type=Type.INTEGER),
            "action_type": Schema(type=Type.STRING, enum=[
                "delete_file", "quarantine_file", "remove_registry_key",
                "block_ip", "block_domain", "disable_service",
                "scan_process", "revoke_credential", "patch_vulnerability",
                "reimage_host", "alert_analyst",
            ]),
            "target":  Schema(type=Type.STRING),
            "reason":  Schema(type=Type.STRING),
        },
        required=["priority", "action_type", "target", "reason"],
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
actions (process kills, IP/domain blocks). Those actions are marked as EXECUTED in
your context. Your job is NOT to re-triage. It is to answer:

  1. PERSISTENCE  — Did the attacker plant any mechanisms that survive a reboot?
                    (Registry Run keys, startup files, scheduled tasks, services,
                     WMI subscriptions, DLL hijacking paths.)
                    Are they still ACTIVE?

  2. EXFILTRATION — Was data sent out? To which IPs/domains? Estimate what was stolen
                    (based on file activity before network connections).

  3. BACKDOORS    — Are any injected threads, hollowed processes, or rogue drivers
                    still resident in memory or on disk?

  4. CLEANUP      — Produce a prioritised, machine-executable cleanup action list.
                    Be specific: exact registry key to delete, exact file path to remove,
                    exact IP to block.

  5. IOC LIST     — Extract every artefact that could be used to hunt for this threat
                    on other hosts: file hashes, IPs, domains, registry keys, mutex names.

TOOL USAGE STRATEGY:
  - You MUST call tools before concluding. Do not guess.
  - Start with the blast radius GUIDs. Call get_file_activity and
    get_registry_changes on every process that had a PROCESS_TERMINATION action.
  - Call get_network_activity on every process to find C2 / exfil endpoints.
  - If you find injections, call get_injection_chains on the source process.
  - If you find suspicious children, call get_child_processes then investigate each.
  - Be exhaustive: cover EVERY guid in blast_radius_guids.

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
          3 — Executed actions
          4 — Process lineage (ancestry chain + blast radius)
          5 — Process action summaries (what each process DID)
          6 — Injection victims
          7 — Task instructions
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

        # ── Section 3: Executed actions ───────────────────────────────────────
        lines += ["═" * 80, "EXECUTED ACTIONS (containment already performed)", "═" * 80]
        for act in context_payload.get("executed_actions", []):
            lines.append(
                f"  [{act.get('status', '?')}] {act.get('action')} "
                f"→ {act.get('target_type')}={act.get('target_value')}  "
                f"at={act.get('executed_at', '?')}"
            )
        lines.append("")

        # ── Section 4: Process lineage ────────────────────────────────────────
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

        # ── Section 5: Process action summaries ───────────────────────────────
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

        # ── Section 6: Injection victims ──────────────────────────────────────
        if context_payload.get("injection_victims"):
            lines += ["═" * 80, "INJECTION VICTIMS (scan — do NOT kill)", "═" * 80]
            for vic in context_payload["injection_victims"]:
                lines.append(
                    f"  GUID={vic.get('guid')}  image={vic.get('image', '?')} "
                    f"injected_by={vic.get('injected_by', '?')} "
                    f"signed={vic.get('signed', '?')}"
                )
            lines.append("")

        # ── Section 7: Task ───────────────────────────────────────────────────
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
            "For EACH guid:",
            "  1. get_file_activity      — dropped files / persistence droppers.",
            "  2. get_network_activity   — C2 / exfil endpoints.",
            "  3. get_registry_changes   — persistence keys.",
            "  4. get_injection_chains   — remote thread injections.",
            "  5. get_loaded_drivers     — unsigned kernel drivers.",
            "  6. Follow suspicious leads (get_child_processes, get_process_tampering).",
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
                category=    f.get("category",    "other"),
                severity=    f.get("severity",    "medium"),
                guid=        f.get("guid",        ""),
                description= f.get("description", ""),
                evidence=    f.get("evidence",    {}),
                iocs=        f.get("iocs",        []),
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
        """
        Save the final RemediationReport to remediation_reports/<incident_id>.json.
        """
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
