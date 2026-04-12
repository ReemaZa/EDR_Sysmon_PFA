# L1 Hash Reputation Engine - Complete Documentation

## 📋 **Table of Contents**
1. [Overview](#overview)
3. [Architecture](#architecture)
4. [Installation & Setup](#installation--setup)
5. [Usage Guide](#usage-guide)
6. [Tools Reference](#tools-reference)
7. [API Configuration](#api-configuration)
8. [Troubleshooting](#troubleshooting)
9. [Future Work](#future-work)
10. [Performance Metrics](#performance-metrics)

---

## 🎯 **Overview**

The L1 Hash Reputation Engine is a **3-tier detection system** that checks file hashes against:
1. **Whitelist table** - Known good files (NSRL, Windows systems)
2. **MalwareBazaar offline DB** - 1-2M known malware hashes
3. **MalwareBazaar API** - Real-time lookups for unknown hashes

**Key Features:**
- ✅ Early exit on first malicious hash
- ✅ Separate tables for whitelist/malware
- ✅ Offline operation (95%+ coverage)
- ✅ Comprehensive statistics

---

## 🏗️ **Architecture**

### **Data Flow**

```
Sysmon Event (XML)
    ↓
ingestion.parse_sysmon_event()
    ↓
event = {
    'event_id': 1,
    'data': {
        'Hashes': 'MD5=abc,SHA256=def',  ← For Sigma (raw)
        'Image': 'C:\\malware.exe'
    },
    'hashes': {'md5': 'abc', 'sha256': 'def'}  ← For L1 (parsed)
}
    ↓
pipeline.process_event(event)
    ↓
l1_engine.check_event(event)
    ↓
Extract SHA256 from event['hashes']
    ↓
Check: Whitelist → MalwareBazaar DB → API
    ↓
Return DetectionResult or None
```

### **Database Schema**

```sql
-- malware_intelligence.db

TABLE: malwarebazaar_hashes
    hash TEXT PRIMARY KEY
    file_name TEXT
    file_type TEXT
    signature TEXT
    first_seen TEXT
    reporter TEXT
    metadata TEXT (JSON)

TABLE: whitelist_hashes
    hash TEXT PRIMARY KEY
    source TEXT (nsrl/windows_system/custom)
    product_name TEXT
    added_date TIMESTAMP
```

---

## 🚀 **Installation & Setup**

### **Step 1: Install Dependencies**

```bash
pip install -r requirements.txt
```

### **Step 2: Download MalwareBazaar Database**
go to https://bazaar.abuse.ch/export/#csv and download csv file full data dump  then put the csv file inside the folder l1_hash_check 
then u can run this command to import the hashes from the csv file to the sqlite db 
this operation will be later automated 
```bash

# Import to database (SHA256 only - recommended)
python malwarebazaar_importer.py full.csv --hash-type sha256

# This creates: data/malware_intelligence.db with ~1-2M hashes
```

**Expected Time:** 5-10 minutes for import u can type ctrl c to stop the import after few file are imported because right now we are just testing

### **Step 3: Set API Key (Optional)**
create a an account in malware bazaar and generate an api key
then add you api key in the env file like this 
MALWAREBAZAAR_API_KEY=6e....




---

## 📖 **Usage Guide**

### **Basic Usage in Pipeline**
to desactivate the hash scan just change enable_l1 to false
```python

# Initialize pipeline with L1 enabled
pipeline = DetectionPipeline(
    enable_l1=True,   # ✅ Hash reputation
    enable_l2=True,   # Sigma rules
    enable_l3=False,  # YARA (future)
    enable_l4=False   # AI/ML (future)
)

```


## 🛠️ **Tools Reference**

All tools are located in `/tools` directory.

### **1. add_hash_toWhiteList.py**

**Purpose:** Add trusted hashes to whitelist table ( for now we do this manually , in the future we would have a db that contains the the hash whitelist)

**Usage:**
```bash
python tools/add_hash_toWhiteList.py
```

**Customize:**
```python
# Edit the file to add your hashes
trusted_files = [
    {
        "hash": "60c04034a1e21d71588bc3266c9b4f924032aefe...",
        "name": "Windows cmd.exe",
        "source": "windows_system"
    },
    # Add more...
]
```

**Sources:**
- `windows_system` - Windows system files
- `nsrl` - NSRL database
- `vendor_standard` - Vendor software (Chrome, Firefox, etc.)
- `custom` - Your custom trusted files

---

### **2. test_api_malware_bazaar.py**

**Purpose:** Test MalwareBazaar API connection by sending  a hash 

**Usage:**
```bash
# Make sure API key is set first!

python tools/test_api_malware_bazaar.py
```

**Expected Output:**
```
[+] Using API key: 6ee43d...e08c
[+] Testing API connection...
[+] Response status: 200
[✓] API is working!
    File: eicar.com
    Signature: EICAR-Test-File
```

**Troubleshooting:**
- **401 Unauthorized:** Wrong API key
- **429 Too Many Requests:** Rate limit hit
- **Connection Error:** No internet or API down

---

### **3. check_malware_intelligence_db.py**

**Purpose:** View database contenu 

**Usage:**
```bash
python tools/check_malware_intelligence_db.py
```

**Output:**
```
Database Stats:
  Malware hashes:   1,500,000
  Whitelist hashes: 150
  Total:            1,500,150
```

---

### **4. test_hash_system.py**

**Purpose:** Comprehensive test of the entire hash system

**Usage:**
```bash
python tools/test_hash_system.py
```

**What it tests:**
1. Database creation
2. Hash insertion
3. Whitelist functionality
4. Malware table lookup
5. Early exit behavior
6. Statistics tracking

**Expected Output:**
```
[TEST 1] Database Initialization
✓ PASS

[TEST 2] Whitelist Check
✓ PASS - Whitelisted hash skipped

[TEST 3] Malware Detection
✓ PASS - Malicious hash detected

✅ ALL TESTS COMPLETED
```

---

## 🔑 **API Configuration**



### .env File**

Create `.env` in project root:
```
MALWAREBAZAAR_API_KEY=6ee43d1234567890abcdefeb55b29e08c
```

Engine automatically loads it with `python-dotenv`.

### **API Rate Limits**

**it is just a configuration for now - malware bazaar api rate limits are not clear it is way better than virus total :**
- 100 requests per day
- Resets every 24 hours
- Engine tracks usage automatically

**Engine Behavior:**
- Stops at 100 queries
- Shows warning message
- Continues with offline DB only

---


## 🚧 **Future Work**


### **Priority 2: Feature Enhancements**

1. **Add NSRL Whitelist Support** ⏱️ 2-3 hours
   - Download NSRL database
   - Create NSRL importer (similar to MalwareBazaar)
   - Import to whitelist table
   - **Benefit:** 50M+ known-good hashes

2. **Implement Caching Layer** ⏱️ 1-2 hours
   ```sql
   -- Add cache table for API results
   CREATE TABLE api_cache (
       hash TEXT PRIMARY KEY,
       verdict TEXT,
       last_checked TIMESTAMP,
       ttl_hours INTEGER
   );
   ```
   - Cache API results for 24 hours
   - Reduce API usage
   - Faster repeat lookups

3. **Add Hash Type Flexibility** ⏱️ 1 hour
   ```python
   def __init__(self, hash_types=['sha256']):
       """Support MD5, SHA1, SHA256, or all"""
       self.hash_types = hash_types
   ```
   - Currently only SHA256
   - Add support for MD5/SHA1 if needed

4. **Batch API Lookups** ⏱️ 2 hours
   ```python
   def check_multiple_hashes(self, hashes: List[str]):
       """Check multiple hashes in one API call"""
       # MalwareBazaar supports batch lookups
   ```

5. **Add Windows System Hash Extractor** ⏱️ 3 hours
   ```python
   # tools/extract_windows_hashes.py
   # Automatically hash common Windows files
   # Add to whitelist table
   ```

---

### **Priority 3: Performance Optimizations**

1. **Database Indexing** ⏱️ 30 min
   ```sql
   CREATE INDEX idx_hash_prefix ON malwarebazaar_hashes(substr(hash, 1, 8));
   ```
   - Faster lookups for large DBs

2. **Connection Pooling** ⏱️ 1 hour
   ```python
   # Use SQLite connection pool
   # Reduce overhead on frequent checks
   ```

3. **Async API Calls** ⏱️ 2 hours
   ```python
   async def _check_api_async(self, hashes):
       """Check multiple hashes concurrently"""
   ```

---

### **Priority 4: Monitoring & Analytics**

1. **Add Performance Metrics** ⏱️ 1 hour
   ```python
   self.stats['avg_lookup_time_ms'] = ...
   self.stats['fastest_lookup_ms'] = ...
   self.stats['slowest_lookup_ms'] = ...
   ```

2. **Export Statistics to File** ⏱️ 30 min
   ```python
   engine.export_stats('stats.json')
   ```

3. **Daily Report Generation** ⏱️ 1 hour
   ```python
   # Automatic daily summary
   # Email or log file
   ```

---

### **Priority 5: Integration**

1. **Add VirusTotal Support** ⏱️ 3 hours
   - Alternative to MalwareBazaar
   - Requires paid API
   - More comprehensive data

2. **Add MISP Integration** ⏱️ 4 hours
   - Threat intelligence platform
   - Community-driven IOCs



---

## 📊 **Performance Metrics**

### **Expected Performance**

| Operation | Time | Notes |
|-----------|------|-------|
| Whitelist lookup | <1ms | In-memory hash table |
| DB lookup | <10ms | SQLite indexed lookup |
| API lookup | 1-5s | Network latency |
| Overall avg | 10-20ms | 95% resolve offline |

### **Current Statistics Format**

```python
{
    'total_checks': 1000,
    'malicious_found': 15,
    'clean_found': 985,
    'detection_rate': '1.50%',
    
    'whitelist_hits': 500,      # 50% trusted
    'malware_table_hits': 13,   # Found in DB
    'api_queries': 2,           # Only 2 API calls
    'api_malicious': 2,
    
    'whitelist_size': 150,
    'malware_db_size': 1500000
}
```

---


