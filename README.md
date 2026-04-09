# EDR System - Simplified Version

Multi-layer threat detection system for Windows endpoints using Sysmon events.

## 🎯 Current Status

| Layer | Status | Description |
|-------|--------|-------------|
| L1: Hash Reputation | ✅ **Working on it** | Local blacklist checking |
| L2: Sigma Rules | 🚧 TODO | Behavioral pattern detection |
| L3: YARA Scanner | 🚧 TODO | Malware signature scanning |
| L4: AI/ML Engine | 🚧 TODO | Anomaly detection |

## 📋 Prerequisites

1. **Windows System** (Vista or later)
2. **Python 3.8+**
3. **Administrator privileges**
4. **Sysmon installed** (see installation below)

## 🚀 Quick Start

### 1. Install Sysmon

```powershell
# Download from Microsoft
# https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

# Install with default config
sysmon64.exe -accepteula -i
```

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the EDR Agent with admin privileges

```bash
python -m src.core.agent
```

## 📁 Project Structure

```
edr-sysmon_pfa/
├── ARCHITECTURE.md          # 📖 READ THIS! Defines all data formats
├── src/
│   ├── core/
│   │   └── agent.py                # Main agent orchestrator
│   │   ├── event_watcher.py        # Sysmon event subscription - (gets sysmon events in real time)
│   │   ├── ingestion.py            # Event parsing & normalization
│   │   ├── pipeline.py             # Detection pipeline orchestrator
│   └── detection/
│       ├── l1_hash_reputation.py   # ✅ Hash checker (working on it )
│       ├── l2_sigma_engine.py      # 🚧 Placeholder
│       ├── l3_yara_scanner.py      # 🚧 Placeholder
│       └── l4_ai_engine.py         # 🚧 Placeholder
└── config/ioc/
    └── hash_blacklist.txt   # Add malicious hashes here
```

## 🔍 How L1 Works

1. **Load blacklist** - Reads hashes from `config/ioc/hash_blacklist.txt`
2. **Event arrives** - Agent receives Sysmon event
3. **Extract hashes** - Gets SHA256/MD5/SHA1 from event
4. **Check blacklist** - Compares against loaded hashes
5. **Alert** - If match found, returns CRITICAL threat

### Example Output

```
[L1-HASH] Engine initialized
[L1-HASH] Blacklist size: 3 hashes

🔴 ALERT [ 1] 2024-01-15 10:24:12 | ProcessCreate | Threat: CRITICAL
       └─ L1-Hash: CRITICAL - Hash 275a021bbfb6489... found in blacklist
```

## 📖 Conseils 

### **READ ARCHITECTURE.md FIRST **

Before implementing any layer, read [`ARCHITECTURE.md`](ARCHITECTURE.md) to understand:
- Input format (what you receive)
- Output format (what you must return)
- DetectionResult structure
- ThreatLevel enum values

### Implementing a New Layer

1. **Copy a placeholder file** (e.g., `l2_sigma_engine.py`)
2. **Follow the interface**:
   ```python
   def check_event(self, event: Dict) -> Optional[DetectionResult]:
       # Your detection logic here
       if threat_found:
           return DetectionResult(
               layer_name="L2-YourLayer",
               threat_level=ThreatLevel.HIGH,
               matches=["What you detected"],
               metadata={'extra': 'info'}
           )
       return None
   ```
3. **Test independently** - Each layer can be tested alone
4. **Integrate** - Pipeline automatically uses your layer

## 🧪 Testing

### Test L1 Engine

```python
from src.detection.l1_hash_reputation import HashReputationEngine

# Create engine
engine = HashReputationEngine()

# Add test hash
engine.add_hash_to_blacklist("abc123def456")

# Create fake event
event = {
    'event_id': 1,
    'event_type': 'ProcessCreate',
    'hashes': 'SHA256=abc123def456',
    'image': 'C:\\test.exe'
}

# Check it
result = engine.check_event(event)
print(result)  # Should detect malicious hash
```

## 📊 Statistics

The pipeline tracks:
- Total events processed
- Alerts generated
- Detections per layer
- Engine-specific stats

View stats by pressing `Ctrl+C` to stop the agent.

## 🛠️ Configuration

### Add Malicious Hashes

Edit `config/ioc/hash_blacklist.txt`:
```
# Add hashes (one per line)
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
44d88612fea8a8f36de82e1278abb02f
```

### Enable/Disable Layers

In `src/core/agent.py`:
```python
pipeline = DetectionPipeline(
    enable_l1=True,   # Hash reputation
    enable_l2=False,  # Sigma (not implemented)
    enable_l3=False,  # YARA (not implemented)
    enable_l4=False   # AI (not implemented)
)
```

## 🎓 Next Steps

### To implement L2 (Sigma):
1. Install: `pip install pysigma`
2. Load rules from `config/sigma_rules/`
3. Match event fields against rules
4. Return DetectionResult

### To implement L3 (YARA):
1. Install: `pip install yara-python`
2. Compile rules from `config/yara_rules/`
3. Scan file paths from events
4. Return DetectionResult

### To implement L4 (AI):
1. Train/load ML models
2. Extract features from events
3. Run inference
4. Return DetectionResult

## ❓ FAQ

**Q: Where do I add malicious hashes?**  
A: Edit `config/ioc/hash_blacklist.txt`

**Q: How do I know what format to return?**  
A: Read `ARCHITECTURE.md` - it defines everything!

**Q: Can I test my layer independently?**  
A: Yes! Each layer is independent. Just import and test.




