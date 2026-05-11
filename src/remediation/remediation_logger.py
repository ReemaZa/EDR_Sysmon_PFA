"""
remediation_logger.py  —  Structured, human-readable logger for the Remediation Module.

PURPOSE
-------
Every step of the remediation pipeline writes to this logger. The output goes to:
  1. Console (stdout) — same as before, so nothing breaks.
  2. remediation_logs/remediation_<timestamp>.log — a detailed, structured
     text file you can open to trace exactly what happened, in what order,
     with full data at every step.

LOG STRUCTURE
-------------
The log file is divided into clearly labelled sections separated by banners.
Each section corresponds to one pipeline phase:

  ┌─────────────────────────────────────────────────────────────┐
  │  [PHASE]  REMEDIATION PIPELINE STARTED                      │
  │  [PHASE]  GRACE PERIOD                                      │
  │  [STEP 1] INCIDENT COLLECTION       — Memgraph GUIDs        │
  │  [STEP 2] INCIDENT GROUPING         — union-find clusters   │
  │  [GROUP n] GROUP DETAILS            — members, root         │
  │  [STEP 3] LINEAGE BUILD             — PAT ancestry          │
  │  [STEP 4] CONTEXT BUILD             — LLM payload           │
  │  [STEP 5] REMEDIATION AGENT         — ReAct loop            │
  │    [ROUND n] TOOL CALL              — name, args, result    │
  │    [FINAL]   PROMPT SENT            — full prompt text      │
  │    [FINAL]   LLM RESPONSE           — full JSON             │
  │  [REPORT]  REPORT SUMMARY           — findings, IOCs        │
  │  [PHASE]   PIPELINE COMPLETE                                │
  └─────────────────────────────────────────────────────────────┘

USAGE
-----
    # In remediation_module.py / remediation_agent.py:
    from src.remediation.remediation_logger import RemediationLogger

    # Create one shared logger per pipeline run (passed around):
    logger = RemediationLogger()

    logger.phase("REMEDIATION PIPELINE STARTED")
    logger.step(1, "INCIDENT COLLECTION", "Querying Memgraph for actioned GUIDs")
    logger.info("Found 3 GUIDs")
    logger.data("GUIDs", ["guid-A", "guid-B", "guid-C"])
    logger.error("Something went wrong", exc)
    logger.tool_call(round_=2, name="get_file_activity", args={"guid": "..."}, result={...})
    logger.prompt(text="...")
    logger.llm_response(raw_json={...})
    logger.report_summary(report)
"""

from __future__ import annotations

import json
import os
import sys
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ── Log directory ─────────────────────────────────────────────────────────────
LOG_DIR = "remediation_logs"


class RemediationLogger:
    """
    Thread-safe, structured logger for the remediation pipeline.

    One instance is created at the start of run_remediation() and passed
    to every sub-component (IncidentGrouper, ContextBuilder, RemediationAgent).

    All methods write to both stdout and the log file simultaneously.
    The log file stays open for the lifetime of the logger; call close()
    (or use as a context manager) when the pipeline finishes.
    """

    # Width of the separator banners
    _WIDE  = 90
    _THIN  = 70

    def __init__(self):
        """
        Open the log file immediately on construction so we never lose early output.
        Filename: remediation_logs/remediation_YYYYMMDD_HHMMSS.log
        """
        os.makedirs(LOG_DIR, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.log_path = os.path.join(LOG_DIR, f"remediation_{ts}.log")
        self._lock    = threading.Lock()
        self._handle  = open(self.log_path, "w", encoding="utf-8")

        # Write file header
        self._raw_write(
            "=" * self._WIDE + "\n"
            "  REMEDIATION MODULE — DETAILED EXECUTION LOG\n"
            f"  Started : {datetime.now(timezone.utc).isoformat()}\n"
            f"  Log file: {self.log_path}\n"
            "=" * self._WIDE + "\n\n"
        )
        print(f"[RemediationLogger] Log file opened → {self.log_path}")

    # ── CONTEXT MANAGER ───────────────────────────────────────────────────────

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        """Flush and close the log file."""
        with self._lock:
            if self._handle and not self._handle.closed:
                self._handle.flush()
                self._handle.close()

    # ══════════════════════════════════════════════════════════════════════════
    # PUBLIC LOGGING METHODS
    # ══════════════════════════════════════════════════════════════════════════

    def phase(self, title: str) -> None:
        """
        Top-level pipeline phase banner (double border).
        Use for: pipeline start/end, grace period, fatal errors.

        Example output:
            ══════════════════════════════════════════════════════
            ██  PHASE: REMEDIATION PIPELINE STARTED              ██
            ══════════════════════════════════════════════════════
        """
        ts   = self._ts()
        line = f"  ██  PHASE: {title}"
        self._emit([
            "",
            "═" * self._WIDE,
            f"{line:<{self._WIDE - 2}}  ██",
            f"  {ts}",
            "═" * self._WIDE,
            "",
        ])

    def step(self, number: int, title: str, description: str = "") -> None:
        """
        Numbered pipeline step banner (single border).
        Use for: the 5 numbered pipeline steps in run_remediation().

        Example output:
            ──────────────────────────────────────────────────────
            [STEP 1]  INCIDENT COLLECTION
            Description: Querying Memgraph for actioned GUIDs
            ──────────────────────────────────────────────────────
        """
        ts    = self._ts()
        lines = [
            "",
            "─" * self._WIDE,
            f"[STEP {number}]  {title}",
            f"  Time : {ts}",
        ]
        if description:
            lines.append(f"  About: {description}")
        lines += ["─" * self._WIDE, ""]
        self._emit(lines)

    def group_header(self, index: int, total: int, incident_id: str,
                     root_guid: str, members: List[str]) -> None:
        """
        Header for one incident group being processed.

        Prints the group number, incident ID, root GUID, and every member GUID
        so you can immediately see the scope of this incident.
        """
        lines = [
            "",
            "┌" + "─" * (self._WIDE - 2) + "┐",
            f"│  GROUP {index}/{total}   incident_id={incident_id}",
            f"│  Root GUID   : {root_guid}",
            f"│  Member GUIDs ({len(members)}):",
        ]
        for g in members:
            lines.append(f"│      {g}")
        lines += ["└" + "─" * (self._WIDE - 2) + "┘", ""]
        self._emit(lines)

    def info(self, message: str) -> None:
        """
        Plain informational line.
        Use for short status messages that don't need a data block.

        Example output:
            [12:34:56]  [INFO]  Found 3 actioned GUIDs in Memgraph.
        """
        self._emit([f"  [{self._ts()}]  [INFO]  {message}"])

    def warn(self, message: str) -> None:
        """Warning line — visible but not fatal."""
        self._emit([f"  [{self._ts()}]  [WARN]  ⚠  {message}"])

    def error(self, message: str, exc: Optional[Exception] = None) -> None:
        """
        Error line. If an exception is provided, the full traceback is appended.
        """
        lines = [f"  [{self._ts()}]  [ERROR] ✖  {message}"]
        if exc is not None:
            import traceback
            tb = traceback.format_exc()
            lines += ["    TRACEBACK:", *("    " + l for l in tb.splitlines())]
        self._emit(lines)

    def data(self, label: str, value: Any, indent: int = 4) -> None:
        """
        Pretty-print a labelled data value (list, dict, or scalar).

        If value is a list or dict it is pretty-printed as JSON.
        Scalars are printed inline.

        Example output:
            [DATA] Actioned GUIDs (3 items):
                [
                  "guid-A",
                  "guid-B"
                ]
        """
        pad = " " * indent
        if isinstance(value, (dict, list)):
            rendered = json.dumps(value, indent=2, default=str)
            block    = "\n".join(pad + l for l in rendered.splitlines())
            count    = f" ({len(value)} items)" if isinstance(value, (list, dict)) else ""
            self._emit([f"  [DATA]  {label}{count}:", block])
        else:
            self._emit([f"  [DATA]  {label}: {value}"])

    # ── LINEAGE ───────────────────────────────────────────────────────────────

    def lineage_summary(
        self,
        ancestry_chain:    List[Dict],
        blast_radius:      List[Dict],
        injection_victims: List[Dict],
        chain_truncated:   bool,
    ) -> None:
        """
        Print the full ancestry chain (as an ASCII tree), blast-radius list,
        and injection victims so you can visualise the process tree at a glance.

        Example output:
            [LINEAGE]  Ancestry chain (root → flagged):
              svchost.exe     [pid=832   alive=True   signed=true  IL=System]  GUID=AAA...
                └─ powershell.exe [pid=4912  alive=False  signed=true  IL=High]  GUID=BBB...
                    └─ procdump.exe [pid=6604  alive=False  signed=false IL=High]  GUID=CCC...

            [LINEAGE]  Blast radius (3 node(s)):
              procdump.exe  GUID=CCC...  alive=False
              ...

            [LINEAGE]  Injection victims (1):
              lsass.exe  GUID=DDD...  injected_by=BBB...
        """
        lines = ["", f"  [LINEAGE]  chain_truncated={chain_truncated}"]

        # ── ancestry tree ─────────────────────────────────────────────────────
        lines.append(f"  [LINEAGE]  Ancestry chain (root → flagged, {len(ancestry_chain)} node(s)):")
        for depth, node in enumerate(ancestry_chain):
            prefix = "    " + ("  " * depth) + ("└─ " if depth else "")
            alive_tag = "alive" if node.get("alive") else "dead"
            lines.append(
                f"{prefix}{node.get('image', '?'):<30}  "
                f"pid={str(node.get('pid', '?')):<7}  "
                f"{alive_tag:<5}  "
                f"signed={node.get('signed', '?'):<6}  "
                f"IL={node.get('integrity_level', '?'):<10}  "
                f"GUID={node.get('guid', '?')}"
            )
            if node.get("cmdline"):
                lines.append(f"{'    ' + '  ' * (depth + 1)}cmdline: {node['cmdline'][:150]}")

        # ── blast radius ─────────────────────────────────────────────────────
        lines.append("")
        lines.append(f"  [LINEAGE]  Blast radius ({len(blast_radius)} node(s)):")
        for node in blast_radius:
            alive_tag = "alive" if node.get("alive") else "dead"
            lines.append(
                f"    {node.get('image', '?'):<30}  "
                f"pid={str(node.get('pid', '?')):<7}  "
                f"{alive_tag:<5}  "
                f"GUID={node.get('guid', '?')}"
            )

        # ── injection victims ─────────────────────────────────────────────────
        if injection_victims:
            lines.append("")
            lines.append(f"  [LINEAGE]  Injection victims ({len(injection_victims)}):")
            for v in injection_victims:
                lines.append(
                    f"    {v.get('image', '?'):<30}  "
                    f"GUID={v.get('guid', '?')}  "
                    f"injected_by={v.get('injected_by', '?')}"
                )

        lines.append("")
        self._emit(lines)

    # ── CONTEXT PAYLOAD ───────────────────────────────────────────────────────

    def context_payload(self, payload: Dict[str, Any]) -> None:
        """
        Log the full ContextBuilder JSON payload that the LLM will receive.

        The full payload is printed so you can verify exactly what the agent sees:
        analyst reasoning, executed actions, lineage, process_action_summaries.
        The "actions" list inside blast_radius nodes is stripped for brevity
        (each node's raw PAT stream can be thousands of entries — those are
        fully available in the tool results logged separately).
        """
        # Make a shallow copy so we don't mutate the real payload
        slim = dict(payload)

        # Strip raw actions from blast_radius nodes (too verbose — tools log them)
        if "lineage" in slim:
            slim = dict(slim)
            slim["lineage"] = {
                "ancestry_chain": [
                    {k: v for k, v in n.items() if k != "actions"}
                    for n in slim["lineage"].get("ancestry_chain", [])
                ],
                "blast_radius": [
                    {k: v for k, v in n.items() if k != "actions"}
                    for n in slim["lineage"].get("blast_radius", [])
                ],
            }

        lines = [
            "",
            f"  [CONTEXT]  Full LLM context payload built "
            f"(blast_radius nodes stripped of raw 'actions' for log brevity):",
        ]
        rendered = json.dumps(slim, indent=2, default=str)
        lines += ["    " + l for l in rendered.splitlines()]
        lines.append("")
        self._emit(lines)

    # ── PROMPT ────────────────────────────────────────────────────────────────

    def prompt(self, text: str) -> None:
        """
        Log the full prompt text sent to the LLM on the opening turn.

        This is the most important debug artifact — if the LLM reasons badly,
        the prompt is where to look first.
        """
        border = "▓" * self._WIDE
        lines  = [
            "",
            border,
            "  ▓▓  LLM OPENING PROMPT (full text follows)  ▓▓",
            f"  Characters: {len(text)}",
            border,
        ]
        # Print the prompt verbatim, with line numbers for easy referencing
        for i, line in enumerate(text.splitlines(), 1):
            lines.append(f"  {i:>4} │ {line}")
        lines += [border, ""]
        self._emit(lines)

    # ── REACT ROUND ───────────────────────────────────────────────────────────

    def react_round_start(self, round_: int, max_rounds: int) -> None:
        """Mark the beginning of one ReAct loop iteration."""
        self._emit([
            "",
            f"  ┌─ REACT ROUND {round_}/{max_rounds} "
            f"─────────────────────────── {self._ts()}",
        ])

    def tool_call(
        self,
        round_:    int,
        name:      str,
        args:      Dict[str, Any],
        result:    Dict[str, Any],
    ) -> None:
        """
        Log one tool call: name, arguments, and the full result returned
        by the PAT query function.

        Example output:
            │  [TOOL CALL]  get_file_activity
            │    args   : {"guid": "C2494F38-..."}
            │    result :
            │      {
            │        "guid": "C2494F38-...",
            │        "total_file_events": 3,
            │        "created": [...],
            │        ...
            │      }
        """
        args_str   = json.dumps(args,   indent=6, default=str)
        result_str = json.dumps(result, indent=6, default=str)

        lines = [
            f"  │  [TOOL CALL]  round={round_}  tool={name}",
            f"  │    args   :",
        ]
        for l in args_str.splitlines():
            lines.append(f"  │      {l}")
        lines.append(f"  │    result:")
        for l in result_str.splitlines():
            lines.append(f"  │      {l}")
        lines.append("  │")
        self._emit(lines)

    def react_no_tool_calls(self, round_: int, partial_text: str) -> None:
        """
        Log when the LLM stops calling tools and produces reasoning text.
        Prints the LLM's accumulated reasoning (first 10000 chars) so you can
        see why it decided it was done.
        """
        lines = [
            f"  │  [NO TOOL CALLS]  round={round_} — LLM finished reasoning.",
            f"  │  Partial LLM text (first 10000 chars):",
        ]
        for l in partial_text[:10000].splitlines():
            lines.append(f"  │    {l}")
        if len(partial_text) > 10000:
            lines.append(f"  │    ... [{len(partial_text) - 10000} more chars]")
        self._emit(lines)

    def react_max_rounds(self, max_rounds: int) -> None:
        """Log when the maximum round limit is reached."""
        self._emit([
            f"  └─ [MAX ROUNDS REACHED]  {max_rounds} rounds exhausted. "
            f"Forcing final report.",
        ])

    def react_done(self, rounds_used: int) -> None:
        """Log clean exit from the ReAct loop."""
        self._emit([
            f"  └─ [REACT DONE]  Completed in {rounds_used} round(s).",
        ])

    # ── FORCE-FINAL ───────────────────────────────────────────────────────────

    def force_final_prompt(self, text: str) -> None:
        """
        Log the second (structured-output-only) call to Gemini that forces
        the final report schema. Distinct from the opening prompt so you can
        tell which Gemini call produced what.
        """
        border = "░" * self._WIDE
        lines  = [
            "",
            border,
            "  ░░  FORCE-FINAL PROMPT (structured output call, no tools)  ░░",
            f"  Characters: {len(text)}",
            border,
        ]
        for i, line in enumerate(text.splitlines(), 1):
            lines.append(f"  {i:>4} │ {line}")
        lines += [border, ""]
        self._emit(lines)

    def llm_response(self, raw_json: Dict[str, Any]) -> None:
        """
        Log the full structured JSON response the LLM produced.

        This is the actual report content before it is parsed into
        RemediationReport dataclasses. If the LLM hallucinated a field or
        returned unexpected data, this is where you'll see it.
        """
        border = "▒" * self._WIDE
        lines  = [
            "",
            border,
            "  ▒▒  LLM FINAL RESPONSE (raw structured JSON)  ▒▒",
            border,
        ]
        rendered = json.dumps(raw_json, indent=2, default=str)
        for l in rendered.splitlines():
            lines.append(f"  {l}")
        lines += [border, ""]
        self._emit(lines)

    # ── REPORT SUMMARY ────────────────────────────────────────────────────────

    def report_summary(self, report) -> None:
        """
        Print a complete, human-readable summary of the final RemediationReport.

        Includes:
          - Incident ID + root GUID
          - Every finding (category, severity, guid, description, IOCs)
          - Every cleanup action (priority, type, target, reason)
          - Full IOC list
          - Full narrative
          - Tool call count
        """
        lines = [
            "",
            "★" * self._WIDE,
            f"  ★★  REMEDIATION REPORT SUMMARY",
            f"  Incident ID  : {report.incident_id}",
            f"  Root GUID    : {report.root_guid}",
            f"  Produced at  : {report.produced_at}",
            f"  Tool calls   : {len(report.tool_call_log)}",
            "★" * self._WIDE,
        ]

        # ── Findings ──────────────────────────────────────────────────────────
        lines.append(f"\n  FINDINGS ({len(report.findings)}):")
        if report.findings:
            for i, f in enumerate(report.findings, 1):
                lines += [
                    f"  [{i}] [{f.severity.upper()}] [{f.category}]",
                    f"       GUID       : {f.guid}",
                    f"       Description: {f.description}",
                ]
                if f.iocs:
                    lines.append(f"       IOCs ({len(f.iocs)}): {f.iocs}")
                if f.evidence:
                    ev_str = json.dumps(f.evidence, default=str)
                    lines.append(f"       Evidence   : {ev_str[:300]}")
        else:
            lines.append("  (none)")

        # ── Cleanup actions ───────────────────────────────────────────────────
        lines.append(f"\n  CLEANUP ACTIONS ({len(report.cleanup_actions)}):")
        if report.cleanup_actions:
            for i, a in enumerate(report.cleanup_actions, 1):
                lines += [
                    f"  [{i}] priority={a.get('priority','?')}  "
                    f"type={a.get('action_type','?')}",
                    f"       target : {a.get('target','')}",
                    f"       reason : {a.get('reason','')}",
                ]
        else:
            lines.append("  (none)")

        # ── IOC list ──────────────────────────────────────────────────────────
        lines.append(f"\n  IOC LIST ({len(report.ioc_list)}):")
        for ioc in report.ioc_list:
            lines.append(f"    • {ioc}")

        # ── Narrative ─────────────────────────────────────────────────────────
        lines += [
            "\n  NARRATIVE (full text):",
            "  " + "─" * (self._WIDE - 2),
        ]
        for l in report.narrative.splitlines():
            lines.append(f"  {l}")
        lines += ["  " + "─" * (self._WIDE - 2), ""]

        lines += ["★" * self._WIDE, ""]
        self._emit(lines)

    # ── PIPELINE COMPLETE ─────────────────────────────────────────────────────

    def pipeline_complete(self, report_count: int) -> None:
        """Final banner written at the very end of the pipeline."""
        self._emit([
            "",
            "═" * self._WIDE,
            f"  ██  REMEDIATION PIPELINE COMPLETE",
            f"  Reports produced : {report_count}",
            f"  Finished at      : {datetime.now(timezone.utc).isoformat()}",
            f"  Log file         : {self.log_path}",
            "═" * self._WIDE,
            "",
        ])

    # ══════════════════════════════════════════════════════════════════════════
    # INTERNAL HELPERS
    # ══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def _ts() -> str:
        """UTC timestamp string for log line prefixes."""
        return datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]

    def _emit(self, lines: List[str]) -> None:
        """
        Write all lines to both stdout and the log file, thread-safely.

        A newline is appended to each line. The file gets every line;
        stdout gets the same so you see it in the terminal too.
        """
        text = "\n".join(lines) + "\n"
        with self._lock:
            # stdout
            try:
                sys.stdout.write(text)
                sys.stdout.flush()
            except Exception:
                pass
            # log file
            try:
                self._handle.write(text)
                self._handle.flush()
            except Exception:
                pass

    def _raw_write(self, text: str) -> None:
        """Write directly to the log file (used only for the file header)."""
        with self._lock:
            self._handle.write(text)
            self._handle.flush()
