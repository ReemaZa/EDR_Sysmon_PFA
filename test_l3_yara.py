"""
Quick standalone test for YaraEngine (l3_yara_engine.py)

Tests:
    1. Single file detection (image field)
    2. Multi-file detection (image + target_filename in same event)
    3. Threat level escalation (multiple rules, worst wins)
    4. Redis cache hit (same file scanned twice)
    5. Clean file – no false positive
    6. Missing file – graceful handling
    7. Empty event – no crash
    8. Stats reporting

Run:
        python test_yara_engine.py
"""

import os
import sys
import shutil
import tempfile
import time
import logging

logging.basicConfig(level=logging.WARNING)  # suppress INFO noise during tests

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.detection.l3_yara_scanner import YaraEngine

# ---------------------------------------------------------------------------
# Console colours
# ---------------------------------------------------------------------------
RESET  = "\033[0m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"

def ok(msg):   print(f"  {GREEN}PASS{RESET}  {msg}")
def fail(msg): print(f"  {RED}FAIL{RESET}  {msg}")
def info(msg): print(f"  {YELLOW}INFO{RESET}  {msg}")
def head(msg): print(f"\n{BOLD}{msg}{RESET}")

# ---------------------------------------------------------------------------
# YARA rules used for testing
# ---------------------------------------------------------------------------
CUSTOM_RULES = """
rule Fake_Backdoor
{
    meta:
        description  = "Simulated backdoor"
        threat_level = "high"
        technique    = "T1059"
    strings:
        $s = "FAKE_BACKDOOR_SIGNATURE"
    condition:
        $s
}

rule Fake_Ransomware
{
    meta:
        description  = "Simulated ransomware"
        threat_level = "critical"
        technique    = "T1486"
    strings:
        $s = "FAKE_RANSOMWARE_SIGNATURE"
    condition:
        $s
}

rule Fake_Suspicious
{
    meta:
        description  = "Mildly suspicious"
        threat_level = "medium"
        technique    = "T1055"
    strings:
        $s = "FAKE_SUSPICIOUS_SIGNATURE"
    condition:
        $s
}
"""

TEST_DIR = "test_samples_engine"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def write_file(name: str, content: bytes) -> str:
    """Write content to TEST_DIR/<name> and return absolute path."""
    os.makedirs(TEST_DIR, exist_ok=True)
    path = os.path.abspath(os.path.join(TEST_DIR, name))
    with open(path, "wb") as f:
        f.write(content)
    return path


def setup_rules_dir() -> str:
    """Write CUSTOM_RULES to a temp dir and return its path."""
    rules_dir = tempfile.mkdtemp(prefix="yara_engine_rules_")
    with open(os.path.join(rules_dir, "test_rules.yar"), "w") as f:
        f.write(CUSTOM_RULES)
    return rules_dir


def make_engine(rules_dir: str) -> YaraEngine:
    """Create a YaraEngine with Redis disabled (for isolated testing)."""
    # Pass a non-existent Redis host so Redis is silently disabled
    return YaraEngine(rules_dir=rules_dir, redis_host="localhost", redis_port=1)


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def test_single_file_detection(engine: YaraEngine):
    head("[Test 1] Single file detection – image field")
    path = write_file("backdoor.exe", b"FAKE_BACKDOOR_SIGNATURE extra bytes")
    event = {"event_id": 1, "event_type": "ProcessCreate", "image": path}
    result = engine.check_event(event)
    if result is None:
        fail("No detection – backdoor not caught.")
    else:
        ok(f"Detected  threat={result.threat_level.name}  rules={result.metadata['rule_names']}")


def test_multi_file_detection(engine: YaraEngine):
    head("[Test 2] Multi-file detection – image + target_filename")
    path_img = write_file("process.exe",  b"FAKE_BACKDOOR_SIGNATURE")
    path_tgt = write_file("dropper.dll",  b"FAKE_RANSOMWARE_SIGNATURE")
    event = {
        "event_id": 11,
        "event_type": "FileCreate",
        "image": path_img,
        "target_filename": path_tgt,
    }
    result = engine.check_event(event)
    if result is None:
        fail("No detection – multi-file scan missed both files.")
    else:
        scanned = result.metadata.get("scanned_files", [])
        rules   = result.metadata.get("rule_names", [])
        ok(f"Detected  scanned_files={len(scanned)}  rules={rules}")
        if len(scanned) < 2:
            fail(f"Expected 2 files scanned, got {len(scanned)}")
        else:
            ok("Both files were scanned correctly.")


def test_threat_level_escalation(engine: YaraEngine):
    head("[Test 3] Threat level escalation – worst rule wins")
    # File matches both MEDIUM and CRITICAL rules
    path = write_file("multi.exe", b"FAKE_SUSPICIOUS_SIGNATURE FAKE_RANSOMWARE_SIGNATURE")
    event = {"event_id": 1, "event_type": "ProcessCreate", "image": path}
    result = engine.check_event(event)
    if result is None:
        fail("No detection.")
    elif result.threat_level.name != "CRITICAL":
        fail(f"Expected CRITICAL, got {result.threat_level.name}")
    else:
        ok(f"Correct escalation to CRITICAL (matched: {result.metadata['rule_names']})")


def test_redis_cache_hit(engine: YaraEngine):
    head("[Test 4] Redis cache hit")
    if engine.redis is None:
        info("Redis not available – skipping cache test.")
        return

    path = write_file("cached.exe", b"FAKE_BACKDOOR_SIGNATURE")
    event = {"event_id": 1, "event_type": "ProcessCreate", "image": path}

    # First scan – populates cache
    result1 = engine.check_event(event)
    cache_hits_before = engine.get_stats()["cache_hits"]

    # Second scan – should hit cache
    result2 = engine.check_event(event)
    cache_hits_after = engine.get_stats()["cache_hits"]

    if result1 is None or result2 is None:
        fail("Detection failed on one of the scans.")
    elif cache_hits_after > cache_hits_before:
        ok(f"Cache hit confirmed on second scan. cache_hits={cache_hits_after}")
    else:
        fail("Second scan did not use cache.")


def test_clean_file(engine: YaraEngine):
    head("[Test 5] Clean file – should NOT be flagged")
    path = write_file("clean.exe", b"This is a completely normal file with no signatures.")
    event = {"event_id": 1, "event_type": "ProcessCreate", "image": path}
    result = engine.check_event(event)
    if result is None:
        ok("Correctly returned None for clean file.")
    else:
        fail(f"False positive! Matched: {result.metadata['rule_names']}")


def test_missing_file(engine: YaraEngine):
    head("[Test 6] Missing file – should not crash")
    event = {"event_id": 1, "event_type": "ProcessCreate", "image": "C:\\nonexistent\\file.exe"}
    try:
        result = engine.check_event(event)
        if result is None:
            ok("Returned None gracefully for missing file.")
        else:
            fail(f"Unexpected detection: {result}")
    except Exception as exc:
        fail(f"Crashed with: {exc}")


def test_empty_event(engine: YaraEngine):
    head("[Test 7] Empty event – no file fields")
    event = {"event_id": 3, "event_type": "NetworkConnect", "destination_ip": "1.2.3.4"}
    try:
        result = engine.check_event(event)
        if result is None:
            ok("Returned None gracefully for event with no file paths.")
        else:
            fail(f"Unexpected result: {result}")
    except Exception as exc:
        fail(f"Crashed with: {exc}")


def test_stats(engine: YaraEngine):
    head("[Test 8] Stats reporting")
    stats = engine.get_stats()
    expected = {"total_checks", "files_scanned", "yara_matches",
                "cache_hits", "scan_errors", "rules_loaded"}
    missing = expected - stats.keys()
    if missing:
        fail(f"Missing stat keys: {missing}")
    else:
        ok("All expected stat keys present.")
        for k, v in stats.items():
            info(f"{k:<20} {v}")


# ---------------------------------------------------------------------------
# Performance assessment
# ---------------------------------------------------------------------------

def performance_check(engine: YaraEngine):
    head("[Perf] Scan speed benchmark (100 events)")

    path = write_file("perf_test.exe", b"FAKE_BACKDOOR_SIGNATURE padding " * 100)
    event = {"event_id": 1, "event_type": "ProcessCreate", "image": path}

    # Warm up
    engine.check_event(event)

    start = time.perf_counter()
    for _ in range(100):
        engine.check_event(event)
    elapsed = time.perf_counter() - start

    avg_ms = (elapsed / 100) * 1000
    info(f"100 scans completed in {elapsed:.3f}s  →  avg {avg_ms:.2f}ms per scan")

    if avg_ms < 5:
        ok(f"Excellent – {avg_ms:.2f}ms per scan")
    elif avg_ms < 20:
        ok(f"Good – {avg_ms:.2f}ms per scan")
    elif avg_ms < 50:
        info(f"Acceptable – {avg_ms:.2f}ms per scan (consider Redis caching)")
    else:
        fail(f"Slow – {avg_ms:.2f}ms per scan (Redis caching strongly recommended)")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    # Clean up from previous runs
    if os.path.exists(TEST_DIR):
        shutil.rmtree(TEST_DIR)

    print(f"\n{BOLD}{'='*55}")
    print("  YaraEngine – Full Test Suite")
    print(f"{'='*55}{RESET}")

    rules_dir = setup_rules_dir()
    engine = make_engine(rules_dir)

    if engine.compiled_rules is None:
        print(f"{RED}ERROR: Rules failed to compile. Check yara-python.{RESET}")
        sys.exit(1)

    info(f"Rules loaded: {engine.get_stats()['rules_loaded']}")

    test_single_file_detection(engine)
    test_multi_file_detection(engine)
    test_threat_level_escalation(engine)
    test_redis_cache_hit(engine)
    test_clean_file(engine)
    test_missing_file(engine)
    test_empty_event(engine)
    test_stats(engine)
    performance_check(engine)

    # Summary
    head("Final stats")
    print(f"{'='*55}")
    for k, v in engine.get_stats().items():
        print(f"  {k:<20} {v}")
    print()

    # Cleanup
    shutil.rmtree(rules_dir, ignore_errors=True)
    shutil.rmtree(TEST_DIR, ignore_errors=True)


if __name__ == "__main__":
    main()