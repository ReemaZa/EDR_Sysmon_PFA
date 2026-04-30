from src.detection.l4_llm_detection.action_executor import ActionExecutor


actions = [
    # SAFE process (you choose a known harmless process GUID)
    {
        "id": "act-001",
        "priority": 1,
        "type": "process_termination",
        "target_type": "guid",
        "target_value": "{feade960-af41-69ef-a10b-000000004700}",
        "reason": "Terminate known safe process",
    },

    # SAFE file (create it before test)
    {
        "id": "act-002",
        "priority": 2,
        "type": "file_quarantine",
        "target_type": "file",
        "target_value": "C:\\temp\\edr_test.txt",
        "reason": "Test quarantine",
    },

    {
        "id": "act-003",
        "priority": 3,
        "type": "file_deletion",
        "target_type": "file",
        "target_value": "C:\\temp\\edr_delete.txt",
        "reason": "Test deletion",
    },

    # SAFE networking (loopback only)
    {
        "id": "act-004",
        "priority": 4,
        "type": "ip_block",
        "target_type": "ip",
        "target_value": "127.0.0.1",
        "reason": "Loopback test (safe)",
    },

    {
        "id": "act-005",
        "priority": 5,
        "type": "dns_block",
        "target_type": "domain",
        "target_value": "example.com",
        "reason": "Safe domain test",
    },

    # KEEP blacklist (safe)
    {
        "id": "act-006",
        "priority": 6,
        "type": "blacklist",
        "target_type": "domain",
        "target_value": "test.local",
        "reason": "Blacklist test",
    },

    # SAFE identity (use dummy user that doesn't exist)
    {
        "id": "act-007",
        "priority": 7,
        "type": "identity_revocation",
        "target_type": "user",
        "target_value": "fake_test_user_123",
        "reason": "Non-existing user",
    },

    # SAFE patching (non-critical package name)
    {
        "id": "act-008",
        "priority": 8,
        "type": "patching",
        "target_type": "pkg",
        "target_value": "dummy-package",
        "reason": "Test patching",
    },

    # ALERT (always safe)
    {
        "id": "act-009",
        "priority": 2,
        "type": "alert",
        "target_type": "guid",
        "target_value": "{PUT-YOUR-SAFE-GUID}",
        "reason": "Test alert",
    },

    # NO-OP
    {
        "id": "act-010",
        "priority": 99,
        "type": "nothing",
        "target_type": "",
        "target_value": "",
        "reason": "No operation",
    },
]


executor = ActionExecutor(mode="approval")

results = executor.execute_sync(
    actions=actions,
    anchor_guid="test-anchor-guid"
)

print("\nFINAL RESULTS:")
for r in results:
    print(r)