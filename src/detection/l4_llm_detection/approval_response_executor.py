"""
Reads pending_approvals.jsonl, presents each finding's actions to the operator,
and executes approved ones via ActionExecutor in automatic mode.

Usage:
    python approval_response_executor.py
"""

import json
import os
from pathlib import Path
from src.detection.l4_llm_detection.action_executor import ActionExecutor

PENDING_FILE  = "../../../pending_approvals.jsonl"

def load_pending() -> list[dict]:
    if not Path(PENDING_FILE).exists():
        return []
    with open(PENDING_FILE, "r") as f:
        return [json.loads(line) for line in f if line.strip()]



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

    # Executor always runs in automatic here — approval already happened above
    executor = ActionExecutor(mode="automatic")
    executed_records = []

    for finding in pending:
        if finding.get("executed"):
            print(f"[ApprovalExecutor] Skipping already-executed {finding['analysis_id']}")
            continue

        approved_actions = prompt_finding(finding)

        if not approved_actions:
            continue

        print(f"\n[ApprovalExecutor] Executing {len(approved_actions)} action(s)...")
        results = executor.execute_sync(approved_actions, finding["anchor_guid"])

        finding["executed"]         = True
        finding["approved_actions"] = approved_actions
        finding["results"]          = results
        executed_records.append(finding)

        for r in results:
            status = r.get("status", "?")
            action = r.get("action", "?")
            print(f"  → [{action}] status={status}")

    # Rewrite pending file excluding executed findings
    remaining = [f for f in pending if not f.get("executed")]
    with open(PENDING_FILE, "w") as f:
        for r in remaining:
            f.write(json.dumps(r) + "\n")
    print(f"[ApprovalExecutor] {len(remaining)} finding(s) remain pending.")


if __name__ == "__main__":
    main()