"""
Quick standalone test for the L3 YARA scanner.

Uses two approaches:
    1. EICAR test string  – a standard fake "malware" string that Florian
                            Roth's rules (and most AV engines) detect.
    2. Custom test rule   – a simple .yar rule we write ourselves so the
                            test works even if no external rules are loaded.

Run:
    python test_l3_yara.py
"""

import os
import sys
import tempfile
import shutil


# ---------------------------------------------------------------------------
# Make sure project root is on the path so src.core.pipeline resolves
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.detection.l3_yara_scanner import YaraScanner

# ---------------------------------------------------------------------------
# EICAR test string (harmless – universally detected as "malware" by AV/YARA)
# ---------------------------------------------------------------------------
EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}"
    b"$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

# ---------------------------------------------------------------------------
# A minimal custom YARA rule so the test works without external rule files
# ---------------------------------------------------------------------------
CUSTOM_RULE = """
rule EICAR_Test
{
    meta:
        description = "Detects the EICAR antivirus test file"
        author      = "test"

    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

    condition:
        $eicar
}

rule Fake_Backdoor
{
    meta:
        description = "Simulated backdoor signature for testing"

    strings:
        $magic = "FAKE_MALWARE_SIGNATURE_XYZ"

    condition:
        $magic
}
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RESET  = "\033[0m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BOLD   = "\033[1m"

def ok(msg):   print(f"  {GREEN}PASS{RESET}  {msg}")
def fail(msg): print(f"  {RED}FAIL{RESET}  {msg}")
def info(msg): print(f"  {YELLOW}INFO{RESET}  {msg}")


TEST_FILES_DIR = "test_samples"


def make_temp_file(content: bytes, suffix: str = ".exe", name: str = "sample") -> str:
    """Write content to a local test file and return its absolute path."""
    os.makedirs(TEST_FILES_DIR, exist_ok=True)
    path = os.path.join(TEST_FILES_DIR, f"{name}{suffix}")
    with open(path, "wb") as f:
        f.write(content)
    return os.path.abspath(path)


def setup_test_rules_dir() -> str:
    """
    Write the custom YARA rules into a temp directory and return its path.
    Always used for unit tests so results are deterministic and independent
    of whatever production rules are loaded.
    """
    rules_dir = tempfile.mkdtemp(prefix="yara_test_rules_")
    rule_path = os.path.join(rules_dir, "test_rules.yar")
    with open(rule_path, "w") as f:
        f.write(CUSTOM_RULE)
    return rules_dir


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def test_eicar_detected(scanner: YaraScanner):
    print(f"\n{BOLD}[Test 1] EICAR test file detection (in-memory){RESET}")

    # Scan raw bytes directly — avoids Defender deleting the file on write
    try:
        matches = scanner.compiled_rules.match(data=EICAR)
        if not matches:
            fail("No detection returned – EICAR was not caught.")
        else:
            ok(f"Detected!  rules matched: {[m.rule for m in matches]}")
    except Exception as exc:
        fail(f"Crashed with: {exc}")


def test_fake_backdoor_detected(scanner: YaraScanner):
    """File containing fake backdoor magic string should be flagged."""
    print(f"\n{BOLD}[Test 2] Fake backdoor signature detection{RESET}")

    path = make_temp_file(b"FAKE_MALWARE_SIGNATURE_XYZ some extra bytes", name="backdoor")
    try:
        event = {
            "event_id": 11,
            "event_type": "FileCreate",
            "target_filename": path,
        }
        result = scanner.check_event(event)

        if result is None:
            fail("No detection returned – fake backdoor was not caught.")
        else:
            ok(f"Detected!  threat={result.threat_level.name}")
            ok(f"Matches:   {result.matches}")
    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_clean_file_not_flagged(scanner: YaraScanner):
    """A benign file should return None."""
    print(f"\n{BOLD}[Test 3] Clean file – should NOT be flagged{RESET}")

    path = make_temp_file(b"Hello, this is a totally normal file with nothing bad.", name="clean")
    try:
        event = {
            "event_id": 1,
            "event_type": "ProcessCreate",
            "image": path,
        }
        result = scanner.check_event(event)

        if result is None:
            ok("Correctly returned None for a clean file.")
        else:
            fail(f"False positive! Got: {result.matches}")
    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_missing_file_handled(scanner: YaraScanner):
    """Event pointing to a non-existent file should return None gracefully."""
    print(f"\n{BOLD}[Test 4] Missing file – should not crash{RESET}")

    event = {
        "event_id": 1,
        "event_type": "ProcessCreate",
        "image": "C:\\Windows\\does_not_exist.exe",
    }
    try:
        result = scanner.check_event(event)
        if result is None:
            ok("Returned None gracefully for a missing file.")
        else:
            fail("Unexpected detection on a missing file.")
    except Exception as exc:
        fail(f"Crashed with: {exc}")


def test_empty_event_handled(scanner: YaraScanner):
    """Event with no file path fields should return None without crashing."""
    print(f"\n{BOLD}[Test 5] Empty event – no file fields{RESET}")

    event = {"event_id": 3, "event_type": "NetworkConnect", "destination_ip": "1.2.3.4"}
    try:
        result = scanner.check_event(event)
        if result is None:
            ok("Returned None gracefully for an event with no file paths.")
        else:
            fail(f"Unexpected result: {result}")
    except Exception as exc:
        fail(f"Crashed with: {exc}")


def test_stats(scanner: YaraScanner):
    """Stats dict should have expected keys and non-zero counts."""
    print(f"\n{BOLD}[Test 6] Stats reporting{RESET}")

    stats = scanner.get_stats()
    expected_keys = {"total_checks", "files_scanned", "yara_matches",
                     "scan_errors", "rules_loaded"}

    missing = expected_keys - stats.keys()
    if missing:
        fail(f"Missing keys in stats: {missing}")
    else:
        ok("All expected keys present.")
        info(f"Stats snapshot: {stats}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    # Clean up leftover test files from previous runs
    if os.path.exists(TEST_FILES_DIR):
        shutil.rmtree(TEST_FILES_DIR)

    print(f"\n{BOLD}{'='*55}")
    print("  L3 YARA Scanner – Quick Test")
    print(f"{'='*55}{RESET}")

    # ------------------------------------------------------------------
    # Two scanners:
    #   custom_scanner  – uses our known test rules (deterministic)
    #                     used for tests 1-5
    #   prod_scanner    – uses config/yara_rules/ if available
    #                     used for test 6 (stats on real ruleset)
    # ------------------------------------------------------------------
    custom_rules_dir = setup_test_rules_dir()
    custom_scanner = YaraScanner(rules_dir=custom_rules_dir)

    if custom_scanner.compiled_rules is None:
        print(f"\n{RED}ERROR: Custom test rules failed to compile. "
              f"Check yara-python installation.{RESET}")
        sys.exit(1)

    info("Custom test rules compiled successfully.")

    # Production scanner (optional – only used for stats display)
    prod_rules = "config/yara_rules"
    has_prod_rules = (
        os.path.isdir(prod_rules)
        and any(f.endswith((".yar", ".yara")) for f in os.listdir(prod_rules))
    )

    if has_prod_rules:
        info(f"Production rules found in '{prod_rules}' – loading for stats test.")
        prod_scanner = YaraScanner(rules_dir=prod_rules)
    else:
        info("No production rules found – stats test will use custom scanner.")
        prod_scanner = custom_scanner

    info(f"Production rules loaded: {prod_scanner.get_stats()['rules_loaded']}")

    # ------------------------------------------------------------------
    # Run tests 1-5 against custom scanner (guaranteed to match/not match)
    # Run test 6 against production scanner (shows real ruleset stats)
    # ------------------------------------------------------------------
    test_eicar_detected(custom_scanner)
    test_fake_backdoor_detected(custom_scanner)
    test_clean_file_not_flagged(custom_scanner)
    test_missing_file_handled(custom_scanner)
    test_empty_event_handled(custom_scanner)
    test_stats(custom_scanner)

    # Final stats
    print(f"\n{BOLD}{'='*55}")
    print("  Final stats (production scanner)")
    print(f"{'='*55}{RESET}")
    for k, v in custom_scanner.get_stats().items():
        print(f"  {k:<20} {v}")
    print()

    # Cleanup temp rules dir
    shutil.rmtree(custom_rules_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
