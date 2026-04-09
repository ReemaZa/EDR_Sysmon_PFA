"""
Simple Test for L1 Hash Reputation Engine

This script tests the hash engine independently (no Sysmon needed).
"""
from src.detection.l1_hash_reputation import HashReputationEngine
from src.core.pipeline import ThreatLevel

print("="*60)
print("L1 HASH REPUTATION ENGINE - TEST")
print("="*60)

# Create engine
print("\n1. Creating engine...")
engine = HashReputationEngine()

# Add a test hash to blacklist
print("\n2. Adding test hash to blacklist...")
test_hash = "abc123def456789012345678901234567890123456789012345678901234"
engine.add_hash_to_blacklist(test_hash)

# Create a fake event with malicious hash
print("\n3. Testing malicious event...")
malicious_event = {
    'event_id': 1,
    'event_type': 'ProcessCreate',
    'event_record_id': 12345,
    'image': 'C:\\Windows\\System32\\malware.exe',
    'hashes': f'SHA256={test_hash},MD5=abc123'
}

result = engine.check_event(malicious_event)

if result:
    print("   ✅ PASS - Malicious hash detected!")
    print(f"   Layer: {result.layer_name}")
    print(f"   Threat: {result.threat_level.name}")
    print(f"   Matches: {result.matches}")
    print(f"   Metadata: {result.metadata}")
    assert result.threat_level == ThreatLevel.CRITICAL
else:
    print("   ❌ FAIL - Should have detected malicious hash")

# Create a fake event with clean hash
print("\n4. Testing clean event...")
clean_event = {
    'event_id': 1,
    'event_type': 'ProcessCreate',
    'event_record_id': 12346,
    'image': 'C:\\Windows\\System32\\notepad.exe',
    'hashes': 'SHA256=zzz999yyy888xxx777www666vvv555uuu444ttt333sss222rrr111qqq000'
}

result = engine.check_event(clean_event)

if result is None:
    print("   ✅ PASS - Clean hash (no detection)")
else:
    print("   ❌ FAIL - Should not have detected clean hash")

# Test event with no hashes
print("\n5. Testing event with no hashes...")
no_hash_event = {
    'event_id': 3,
    'event_type': 'NetworkConnect',
    'event_record_id': 12347,
    'destination_ip': '192.168.1.1'
}

result = engine.check_event(no_hash_event)

if result is None:
    print("   ✅ PASS - No hashes (skipped)")
else:
    print("   ❌ FAIL - Should have skipped event with no hashes")

# Print statistics
print("\n6. Engine Statistics:")
stats = engine.get_stats()
print(f"   Total Checks: {stats['total_checks']}")
print(f"   Blacklist Hits: {stats['blacklist_hits']}")
print(f"   Blacklist Size: {stats['blacklist_size']}")

print("\n" + "="*60)
print("✅ ALL TESTS COMPLETED")
print("="*60)
