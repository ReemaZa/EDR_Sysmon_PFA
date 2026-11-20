"""
Reads pending_approvals.jsonl, presents each finding's actions to the operator,
and executes approved ones via ActionExecutor in automatic mode.

The queue file is APPEND-ONLY from this tool's point of view: it is never
rewritten, because the agent may append new findings while the operator is
still reviewing (a rewrite would silently drop them). Executed findings are
recorded in approvals_resolved.jsonl instead, and load_pending() hides every
finding whose analysis_id appears there.

Usage (from the repo root):
    python -m src.detection.l4_llm_detection.approval_response_executor
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from src.detection.l4_llm_detection.action_executor import ActionExecutor
from src.core.config import APPROVALS_RESOLVED_FILE, PENDING_APPROVALS_FILE

# Same file the ThreatAnalyst and the Remediation module write to
# (relative to the working directory - run this from the repo root).
PENDING_FILE  = PENDING_APPROVALS_FILE
RESOLVED_FILE = APPROVALS_RESOLVED_FILE


def _read_jsonl(path: str) -> list[dict]:
    """Read a JSONL file, skipping blank or half-written lines (the agent may
    be appending to the file at this very moment)."""
    if not Path(path).exists():
        return []
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def load_pending() -> list[dict]:
    """Queued findings that have not been executed yet."""
    resolved_ids = {r.get("analysis_id") for r in _read_jsonl(RESOLVED_FILE)}
    return [
        f for f in _read_jsonl(PENDING_FILE)
        if f.get("analysis_id") not in resolved_ids and not f.get("executed")
    ]


def _mark_resolved(finding: dict, approved_actions: list[dict], results: list[dict]) -> None:
    """Append one line to the resolved log. Append-only: never touches the queue."""
    record = {
        "analysis_id":      finding["analysis_id"],
        "resolved_at":      datetime.now(timezone.utc).isoformat(),
        "approved_actions": approved_actions,
        "results":          results,
    }
    with open(RESOLVED_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")



def prompt_finding(finding: dict) -> list[dict]:
    """
    Presents a finding to the operator.
    Returns the list of approved actions.
    """
    print(f"\n{'=' * 70}")
    print(f"  Analysis ID : {finding['analysis_id']}")
    print(f"  Anchor GUID : {finding['anchor_guid']}")
    print(f"  Verdict     : {finding['verdict']}")
    print(f"  Produced at : {finding['produced_at']}")
    print(f"  Actions ({len(finding['actions'])}):")
    for i, action in enumerate(finding['actions'], 1):
        print(
            f"\n    [{i}] {action['type'].upper()}  (priority={action['priority']})\n"
            f"        target : {action['target_type']}={action['target_value']}\n"
            f"        reason : {action['reason']}"
        )
    print(f"\n{'=' * 70}")
    print("  Options: [a]pprove all  |  [y/n] per action  |  [s]kip finding")

    choice = input("\n  > ").strip().lower()

    if choice in ("s", "skip"):
        print("  ⏭  Finding skipped.")
        return []

    if choice in ("a", "all"):
        print(" All actions approved.")
        return finding["actions"]

    # Per-action approval
    approved = []
    for action in finding["actions"]:
        ans = input(
            f"\n  Approve [{action['type']}] on {action['target_value']!r}? [y/N]: "
        ).strip().lower()
        if ans in ("y", "yes"):
            approved.append(action)
            print(f" Approved.")
        else:
            print(f" Rejected.")
    return approved


def main():
    pending = load_pending()
    if not pending:
        print("[ApprovalExecutor] No pending approvals found.")
        return

    print(f"[ApprovalExecutor] {len(pending)} pending finding(s) to review.\n")

    # Executor always runs in automatic here — approval already happened above,
    # so pre_approved=True lifts the approval-only gate (shutdown, isolation...).
    executor = ActionExecutor(mode="automatic", pre_approved=True)
    executed_count = 0

    for finding in pending:
        approved_actions = prompt_finding(finding)

        if not approved_actions:
            continue

        print(f"\n[ApprovalExecutor] Executing {len(approved_actions)} action(s)...")
        results = executor.execute_sync(approved_actions, finding["anchor_guid"])

        _mark_resolved(finding, approved_actions, results)
        executed_count += 1

        for r in results:
            status = r.get("status", "?")
            action = r.get("action", "?")
            print(f"  → [{action}] status={status}")

    # The queue is not rewritten (see module docstring). Re-read it to report
    # the real number still pending, including findings added during review.
    print(
        f"[ApprovalExecutor] {executed_count} finding(s) executed, "
        f"{len(load_pending())} remain pending."
    )


if __name__ == "__main__":
    main()