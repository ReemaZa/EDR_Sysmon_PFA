# EDR Detection System - Architecture Documentation

## 📋 DATA STRUCTURES & INTERFACES

This document defines EXACTLY what each layer returns and what format to use.
**Every team member must follow these formats!**

---

## 🎯 DETECTION LAYER INTERFACE

Every detection layer (L1, L2, L3, L4) must implement this interface:

### Function Signature
```python
def check_event(self, event: Dict[str, Any]) -> Optional[DetectionResult]:
    """
    Check event for threats.
    
    INPUT: Event dictionary (see format below)
    OUTPUT: DetectionResult if threat found, None if clean
    """
```

---

## 📥 INPUT FORMAT: Event Dictionary

This is what each layer receives as input (the sysmon event log after the parsing done in ingestion.py ):

```python
event = {
    # === CORE FIELDS (always present) ===
    'event_id': 1,                          # int - Sysmon event ID
    'event_type': 'ProcessCreate',         # str - Event type name
    'event_record_id': 12345,               # int - Unique Windows event record ID
    'timestamp': '2024-01-15T10:30:45',    # str - ISO format timestamp
    
    # === PROCESS FIELDS (Event ID 1) ===
    'image': 'C:\\Windows\\System32\\cmd.exe',           # str - Process executable path
    'command_line': 'cmd.exe /c evil.bat',               # str - Full command line
    'parent_image': 'C:\\Windows\\explorer.exe',         # str - Parent process path
    'parent_command_line': 'explorer.exe',               # str - Parent command
    'user': 'DOMAIN\\username',                          # str - User account
    'process_guid': '{12345-67890}',                     # str - Unique process ID
    'parent_process_guid': '{11111-22222}',              # str - Parent process ID
    'hashes': 'SHA256=abc123,MD5=def456,SHA1=ghi789',   # str - File hashes
    
    # === NETWORK FIELDS (Event ID 3) ===
    'destination_ip': '192.168.1.100',     # str - Target IP
    'destination_port': 443,               # int - Target port
    'source_ip': '10.0.0.5',              # str - Source IP
    'source_port': 54321,                 # int - Source port
    'protocol': 'tcp',                    # str - Protocol
    
    # === FILE FIELDS (Event ID 11) ===
    'target_filename': 'C:\\evil.exe',    # str - File path
    
    # === REGISTRY FIELDS (Event ID 13) ===
    'target_object': 'HKLM\\Software\\...',  # str - Registry key
    'details': 'malicious_value',            # str - Registry value
}
```

**Note:** Not all fields are present in every event. Always use `.get()` to safely access fields.

---

## 📤 OUTPUT FORMAT: DetectionResult

When a layer detects a threat, it returns a `DetectionResult` object:

```python
from src.core.pipeline import DetectionResult, ThreatLevel

result = DetectionResult(
    layer_name="L1-Hash",                    # str - Which layer detected it
    threat_level=ThreatLevel.CRITICAL,       # Enum - How dangerous
    matches=["Hash abc123 in blacklist"],    # List[str] - What was detected
    metadata={'hash': 'abc123'}              # Dict - Extra info
)
```

### ThreatLevel Enum Values
```python
ThreatLevel.UNKNOWN   = 0  # Not sure / no detection
ThreatLevel.LOW       = 1  # Suspicious but not dangerous
ThreatLevel.MEDIUM    = 2  # Potentially malicious
ThreatLevel.HIGH      = 3  # Likely malicious
ThreatLevel.CRITICAL  = 4  # Definitely malicious - BLOCK NOW
```

### DetectionResult Fields

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `layer_name` | str | Which detection layer | "L1-Hash", "L2-Sigma", "L3-YARA" |
| `threat_level` | ThreatLevel | Severity enum | ThreatLevel.CRITICAL |
| `matches` | List[str] | What was detected | ["Rule: Mimikatz", "Hash abc123"] |
| `metadata` | Dict | Extra information | {'rule_id': 'sigma-001', 'confidence': 0.95} |
| `timestamp` | float | When detected (auto-set) | 1705320645.123 |

---

## 📊 FINAL VERDICT FORMAT

The pipeline aggregates all layer results into a `FinalVerdict`:

```python
verdict = FinalVerdict(
    event_id="12345",                    # str - Event identifier
    threat_level=ThreatLevel.CRITICAL    # Enum - Final threat level
)

# Add results from each layer
verdict.layer_results = [
    DetectionResult(...),  # L1 result
    DetectionResult(...),  # L2 result
    # etc.
]

# Final properties
verdict.is_malicious()  # bool - True if HIGH or CRITICAL
verdict.summary()       # str - Human-readable summary
```

---

## 🔍 LAYER-SPECIFIC GUIDELINES

### L1: Hash Reputation

**What to detect:**
- File hashes in blacklist

**Return format:**
```python
DetectionResult(
    layer_name="L1-Hash",
    threat_level=ThreatLevel.CRITICAL,
    matches=["Hash abc123... found in blacklist"],
    metadata={
        'blacklisted_hashes': ['abc123...'],
        'file_path': 'C:\\malware.exe'
    }
)
```

---

### L2: Sigma Rules

**What to detect:**
- Behavioral patterns (suspicious command lines, registry changes, etc.)

**Return format:**
```python
DetectionResult(
    layer_name="L2-Sigma",
    threat_level=ThreatLevel.HIGH,
    matches=["Rule: Mimikatz Execution", "Rule: Suspicious PowerShell"],
    metadata={
        'rule_ids': ['sigma-001', 'sigma-042'],
        'rule_files': ['process_creation.yml', 'powershell.yml']
    }
)
```

---

### L3: YARA Scanner

**What to detect:**
- Malware signatures in files

**Return format:**
```python
DetectionResult(
    layer_name="L3-YARA",
    threat_level=ThreatLevel.CRITICAL,
    matches=["YARA rule: Win32.Trojan.Generic", "YARA rule: Backdoor.Cobalt"],
    metadata={
        'rule_names': ['Win32.Trojan.Generic', 'Backdoor.Cobalt'],
        'scanned_file': 'C:\\suspicious.exe'
    }
)
```

---

### L4: AI/ML Engine

**What to detect:**
- Anomalous behavior using ML models

**Return format:**
```python
DetectionResult(
    layer_name="L4-AI",
    threat_level=ThreatLevel.MEDIUM,
    matches=["ML Model: Anomalous process behavior"],
    metadata={
        'model_name': 'random_forest_v1',
        'confidence': 0.87,
        'features_triggered': ['unusual_parent', 'rare_network_pattern']
    }
)
```

---

## 🚀 IMPLEMENTATION CHECKLIST

For each detection layer, implement:

```python
class YourEngine:
    def __init__(self, config_path: str):
        """Load rules/models/signatures"""
        pass
    
    def check_event(self, event: Dict[str, Any]) -> Optional[DetectionResult]:
        """
        INPUT: Event dictionary (see format above)
        OUTPUT: DetectionResult if threat, None if clean
        """
        # 1. Extract relevant fields from event
        # 2. Run your detection logic
        # 3. If threat found:
        return DetectionResult(
            layer_name="L2-YourLayer",
            threat_level=ThreatLevel.HIGH,
            matches=["What you detected"],
            metadata={'extra': 'info'}
        )
        # 4. If clean:
        return None
    
    def get_stats(self) -> Dict[str, Any]:
        """Return statistics dictionary"""
        return {
            'total_checks': 0,
            'detections': 0
        }
```

---

## 📁 FILE STRUCTURE FOR TEAM

```
src/detection/
├── __init__.py                    # Exports all engines
├── l1_hash_reputation.py          
├── l2_sigma_engine.py           
├── l3_yara_scanner.py           
└── l4_ai_engine.py                
```

Each file is INDEPENDENT - you only need to know:
1. Input format (event dict)
2. Output format (DetectionResult or None)
3. Your detection logic

---

## 🎓 EXAMPLE: Complete Detection Flow

```python
# 1. Event arrives
event = {
    'event_id': 1,
    'event_type': 'ProcessCreate',
    'image': 'C:\\malware.exe',
    'hashes': 'SHA256=abc123...'
}

# 2. L1 checks it
l1_result = l1_engine.check_event(event)
# Returns: DetectionResult(layer_name="L1-Hash", threat_level=CRITICAL, ...)

# 3. L2 checks it
l2_result = l2_engine.check_event(event)
# Returns: DetectionResult(layer_name="L2-Sigma", threat_level=HIGH, ...)

# 4. Pipeline aggregates
verdict = FinalVerdict(event_id="12345", threat_level=CRITICAL)
verdict.layer_results = [l1_result, l2_result]

# 5. Output
print(verdict.is_malicious())  # True
print(verdict.summary())       # "Event 12345: CRITICAL - 2 layer(s) alerted"
```

---

## ✅ TESTING YOUR LAYER

Create a simple test:

```python
# Test your engine
engine = YourEngine()

# Fake event
event = {'event_id': 1, 'image': 'C:\\test.exe'}

# Check it
result = engine.check_event(event)

# Verify
if result:
    print(f"✅ Detection: {result.threat_level.name}")
    print(f"   Matches: {result.matches}")
    print(f"   MetaData {result.metadata}")
else:
    print("✅ Clean - no threat")
```

---

**Questions?** Check this document first! All interfaces are defined here.
