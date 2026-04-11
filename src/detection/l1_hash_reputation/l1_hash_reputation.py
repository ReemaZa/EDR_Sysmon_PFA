"""
Layer 1: Smart Hash Reputation Engine (3-TIER SYSTEM)

PURPOSE:
    Multi-tier hash checking with offline capability and API fallback.
    
ARCHITECTURE:
    TIER 1: In-Memory Blacklist/Whitelist (< 1ms)
        ├─ Instant pass for whitelisted hashes
        ├─ Instant block for blacklisted hashes
        └─ Load from TXT files at startup
    
    TIER 2: SQLite Cache Database (< 50ms)
        ├─ Check cached lookups (previous API calls)
        ├─ Check MalwareBazaar offline DB (1-2M hashes)
        ├─ Respect TTL (auto-expire old entries)
        └─ Works 100% offline
    
    TIER 3: MalwareBazaar API (1-5s, rate limited)
        ├─ Query for unknown hashes only
        ├─ Cache result immediately
        ├─ Fallback when offline DB doesn't have hash
        └─ Rate limit: ~100/day free tier

PERFORMANCE:
    - 95% of lookups resolve in Tier 1-2 (offline, <50ms)
    - 5% go to API (unknown hashes only)
    - Full offline capability after initial DB setup

INPUT:
    Event dictionary with hash fields
    
OUTPUT:
    DetectionResult or None

STATISTICS:
    Tracks performance across all tiers for monitoring
"""
import os
import requests
import time
from typing import Dict, Any, Optional, Set, List
from pathlib import Path

# Import from pipeline
from src.core.utils import DetectionResult, ThreatLevel

# Import hash cache database
from src.detection.hash_cache import HashCacheDB


class SmartHashReputationEngine:
    """
    3-tier hash reputation engine with offline capability.
    
    WORKFLOW:
    1. Check whitelist → PASS (skip everything)
    2. Check blacklist → CRITICAL (instant block)
    3. Check SQLite cache → Use cached result if fresh
    4. Check MalwareBazaar offline DB → Main detection
    5. Check MalwareBazaar API → Unknown hashes only
    6. Return UNKNOWN if all tiers miss
    """
    
    def __init__(self, 
                 blacklist_file: str = "config/ioc/hash_blacklist.txt",
                 whitelist_file: str = "config/ioc/hash_whitelist.txt",
                 db_path: str = "data/hash_cache.db",
                 enable_api: bool = True,
                 api_rate_limit: int = 100):  # Queries per day
        """
        Initialize 3-tier hash reputation engine.
        
        Args:
            blacklist_file: Path to local blacklist TXT file
            whitelist_file: Path to local whitelist TXT file
            db_path: Path to SQLite cache database
            enable_api: Enable MalwareBazaar API lookups
            api_rate_limit: Max API queries per day
        """
        # File paths
        self.blacklist_file = Path(blacklist_file)
        self.whitelist_file = Path(whitelist_file)
        
        # === TIER 1: In-Memory Sets ===
        self.blacklist: Set[str] = set()
        self.whitelist: Set[str] = set()
        self._load_blacklist()
        self._load_whitelist()
        
        # === TIER 2: SQLite Database ===
        self.db = HashCacheDB(db_path)
        
        # === TIER 3: API Configuration ===
        self.enable_api = enable_api
        self.api_rate_limit = api_rate_limit
        self.api_url = "https://mb-api.abuse.ch/api/v1/"
        
        # API rate limiting
        self.api_queries_today = 0
        self.api_reset_time = time.time() + 86400  # Reset after 24h
        
        # === STATISTICS ===
        self.stats = {
            # Overall
            'total_checks': 0,
            'malicious_found': 0,
            'clean_found': 0,
            'unknown': 0,
            
            # Tier 1: Whitelist/Blacklist
            'tier1_whitelist_hits': 0,
            'tier1_blacklist_hits': 0,
            
            # Tier 2: SQLite Cache
            'tier2_cache_hits': 0,
            'tier2_cache_misses': 0,
            'tier2_db_malicious': 0,
            'tier2_db_clean': 0,
            
            # Tier 3: API
            'tier3_api_queries': 0,
            'tier3_api_malicious': 0,
            'tier3_api_clean': 0,
            'tier3_api_errors': 0,
            'tier3_rate_limited': 0,
            
            # Performance
            'avg_lookup_time_ms': 0.0,
            'fastest_lookup_ms': float('inf'),
            'slowest_lookup_ms': 0.0
        }
        
        print(f"[L1-HASH] Smart hash reputation engine initialized")
        print(f"[L1-HASH] Tier 1 - Whitelist: {len(self.whitelist)} hashes")
        print(f"[L1-HASH] Tier 1 - Blacklist: {len(self.blacklist)} hashes")
        print(f"[L1-HASH] Tier 2 - Database: {self.db.count_hashes():,} cached hashes")
        print(f"[L1-HASH] Tier 3 - API: {'Enabled' if enable_api else 'Disabled'}")
    
    # ========================================================================
    # TIER 1: BLACKLIST / WHITELIST
    # ========================================================================
    
    def _load_blacklist(self):
        """Load malicious hashes from TXT file into memory."""
        try:
            if not self.blacklist_file.exists():
                self.blacklist_file.parent.mkdir(parents=True, exist_ok=True)
                self.blacklist_file.touch()
                print(f"[L1-HASH] Created empty blacklist: {self.blacklist_file}")
                return
            
            with open(self.blacklist_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith('#'):
                        self.blacklist.add(line)
            
            print(f"[L1-HASH] Loaded {len(self.blacklist)} hashes from blacklist")
        
        except Exception as e:
            print(f"[L1-HASH] ERROR loading blacklist: {e}")
    
    def _load_whitelist(self):
        """Load trusted hashes from TXT file into memory."""
        try:
            if not self.whitelist_file.exists():
                self.whitelist_file.parent.mkdir(parents=True, exist_ok=True)
                self.whitelist_file.touch()
                print(f"[L1-HASH] Created empty whitelist: {self.whitelist_file}")
                return
            
            with open(self.whitelist_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith('#'):
                        self.whitelist.add(line)
            
            print(f"[L1-HASH] Loaded {len(self.whitelist)} hashes from whitelist")
        
        except Exception as e:
            print(f"[L1-HASH] ERROR loading whitelist: {e}")
    
    # ========================================================================
    # TIER 2: SQLITE CACHE
    # ========================================================================
    
    def _check_cache(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """
        Check SQLite cache (Tier 2).
        
        Returns cached result if exists and not expired.
        """
        cached = self.db.get_hash(file_hash)
        
        if cached:
            self.stats['tier2_cache_hits'] += 1
            
            if cached['verdict'] == 'malicious':
                self.stats['tier2_db_malicious'] += 1
            elif cached['verdict'] == 'clean':
                self.stats['tier2_db_clean'] += 1
            
            return cached
        
        self.stats['tier2_cache_misses'] += 1
        return None
    
    # ========================================================================
    # TIER 3: MALWAREBAZAAR API
    # ========================================================================
    
    def _check_api(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """
        Query MalwareBazaar API (Tier 3).
        
        Only called for unknown hashes. Results are cached immediately.
        
        API ENDPOINT:
            POST https://mb-api.abuse.ch/api/v1/
            
        REQUEST:
            {"query": "get_info", "hash": "abc123..."}
        
        RESPONSE:
            {
                "query_status": "hash_not_found" | "ok",
                "data": [{
                    "sha256_hash": "...",
                    "file_name": "...",
                    "file_type": "...",
                    "signature": "...",
                    ...
                }]
            }
        """
        if not self.enable_api:
            return None
        
        # Check rate limit
        if time.time() > self.api_reset_time:
            # Reset daily counter
            self.api_queries_today = 0
            self.api_reset_time = time.time() + 86400
        
        if self.api_queries_today >= self.api_rate_limit:
            self.stats['tier3_rate_limited'] += 1
            print(f"[L1-HASH] API rate limit reached ({self.api_rate_limit}/day)")
            return None
        
        try:
            self.stats['tier3_api_queries'] += 1
            self.api_queries_today += 1
            
            # Make API request
            response = requests.post(
                self.api_url,
                data={'query': 'get_info', 'hash': file_hash},
                timeout=5
            )
            
            if response.status_code != 200:
                self.stats['tier3_api_errors'] += 1
                return None
            
            result = response.json()
            
            # Hash not found
            if result.get('query_status') == 'hash_not_found':
                # Cache as clean (not in malware DB)
                self.db.add_hash(
                    file_hash,
                    verdict='clean',
                    source='malwarebazaar_api',
                    confidence=0.8,  # Lower confidence for "not found"
                    ttl_hours=24
                )
                self.stats['tier3_api_clean'] += 1
                return {'verdict': 'clean', 'source': 'malwarebazaar_api'}
            
            # Hash found (malicious)
            if result.get('query_status') == 'ok' and result.get('data'):
                data = result['data'][0]  # First result
                
                metadata = {
                    'file_name': data.get('file_name'),
                    'file_type': data.get('file_type'),
                    'signature': data.get('signature'),
                    'first_seen_mb': data.get('first_seen'),
                }
                
                # Cache as malicious
                self.db.add_hash(
                    file_hash,
                    verdict='malicious',
                    source='malwarebazaar_api',
                    confidence=1.0,
                    metadata=metadata,
                    ttl_hours=168  # 7 days
                )
                
                self.stats['tier3_api_malicious'] += 1
                return {
                    'verdict': 'malicious',
                    'source': 'malwarebazaar_api',
                    'metadata': metadata
                }
        
        except requests.exceptions.Timeout:
            print(f"[L1-HASH] API timeout for hash {file_hash[:16]}...")
            self.stats['tier3_api_errors'] += 1
        
        except Exception as e:
            print(f"[L1-HASH] API error: {e}")
            self.stats['tier3_api_errors'] += 1
        
        return None
    
    # ========================================================================
    # HASH EXTRACTION
    # ========================================================================
    
    def _extract_hashes_from_event(self, event: Dict[str, Any]) -> List[str]:
        """
        Extract all file hashes from Sysmon event.
        
        Looks for: 'hashes', 'md5', 'sha1', 'sha256'
        """
        hashes = []
        
        # Parse "Hashes" field (Event ID 1)
        if 'hashes' in event:
            hash_str = event['hashes']
            for part in hash_str.split(','):
                if '=' in part:
                    hash_type, hash_value = part.split('=', 1)
                    hash_value = hash_value.strip().lower()
                    if hash_value and len(hash_value) >= 32:
                        hashes.append(hash_value)
        
        # Individual hash fields
        for field in ['md5', 'sha1', 'sha256']:
            if field in event:
                hash_val = str(event[field]).strip().lower()
                if hash_val and len(hash_val) >= 32:
                    hashes.append(hash_val)
        
        # Remove duplicates
        return list(set(hashes))
    
    # ========================================================================
    # MAIN CHECK FUNCTION
    # ========================================================================
    
    def check_event(self, event: Dict[str, Any]) -> Optional[DetectionResult]:
        """
        Check event through 3-tier hash reputation system.
        
        WORKFLOW:
        1. Extract hashes from event
        2. For each hash:
           a. Check whitelist (TIER 1) → Skip if trusted
           b. Check blacklist (TIER 1) → CRITICAL if found
           c. Check cache (TIER 2) → Use if fresh
           d. Check API (TIER 3) → Query if unknown
        3. Aggregate results
        4. Return DetectionResult or None
        
        Args:
            event: Normalized Sysmon event dictionary
        
        Returns:
            DetectionResult if malicious, None if clean/unknown
        """
        start_time = time.time()
        self.stats['total_checks'] += 1
        
        # Extract hashes
        hashes = self._extract_hashes_from_event(event)
        
        if not hashes:
            return None
        
        # Track malicious hashes found
        malicious_hashes = []
        detection_sources = []
        metadata = {}
        
        # Check each hash through all tiers
        for file_hash in hashes:
            
            # === TIER 1: WHITELIST (instant pass) ===
            if file_hash in self.whitelist:
                self.stats['tier1_whitelist_hits'] += 1
                continue  # Skip this hash (trusted)
            
            # === TIER 1: BLACKLIST (instant block) ===
            if file_hash in self.blacklist:
                self.stats['tier1_blacklist_hits'] += 1
                malicious_hashes.append(file_hash)
                detection_sources.append('Local blacklist')
                metadata['blacklist_hash'] = file_hash
                continue  # Already found malicious
            
            # === TIER 2: CACHE / OFFLINE DB ===
            cached = self._check_cache(file_hash)
            
            if cached:
                if cached['verdict'] == 'malicious':
                    malicious_hashes.append(file_hash)
                    detection_sources.append(f"Cache ({cached['source']})")
                    if cached.get('metadata'):
                        metadata.update(cached['metadata'])
                continue  # Got result from cache
            
            # === TIER 3: API LOOKUP (last resort) ===
            api_result = self._check_api(file_hash)
            
            if api_result and api_result['verdict'] == 'malicious':
                malicious_hashes.append(file_hash)
                detection_sources.append('MalwareBazaar API')
                if api_result.get('metadata'):
                    metadata.update(api_result['metadata'])
        
        # Update performance stats
        lookup_time = (time.time() - start_time) * 1000  # Convert to ms
        self.stats['avg_lookup_time_ms'] = (
            (self.stats['avg_lookup_time_ms'] * (self.stats['total_checks'] - 1) + lookup_time)
            / self.stats['total_checks']
        )
        self.stats['fastest_lookup_ms'] = min(self.stats['fastest_lookup_ms'], lookup_time)
        self.stats['slowest_lookup_ms'] = max(self.stats['slowest_lookup_ms'], lookup_time)
        
        # If malicious hashes found, create detection result
        if malicious_hashes:
            self.stats['malicious_found'] += 1
            
            # Get file path for metadata
            file_path = event.get('image') or event.get('target_filename') or 'unknown'
            metadata['file_path'] = file_path
            metadata['malicious_hashes'] = malicious_hashes
            
            # Build matches list
            matches = []
            for i, h in enumerate(malicious_hashes):
                short_hash = h[:16] + "..." if len(h) > 16 else h
                source = detection_sources[i] if i < len(detection_sources) else 'unknown'
                matches.append(f"Hash {short_hash} ({source})")
            
            return DetectionResult(
                layer_name="L1-Hash",
                threat_level=ThreatLevel.CRITICAL,
                matches=matches,
                metadata=metadata
            )
        
        # All hashes are clean or unknown
        self.stats['clean_found'] += 1
        return None
    
    # ========================================================================
    # UTILITY FUNCTIONS
    # ========================================================================
    
    def add_hash_to_blacklist(self, file_hash: str):
        """Add hash to local blacklist (memory + file)."""
        file_hash = file_hash.lower().strip()
        
        if file_hash in self.blacklist:
            print(f"[L1-HASH] Hash already in blacklist: {file_hash[:16]}...")
            return
        
        self.blacklist.add(file_hash)
        
        try:
            with open(self.blacklist_file, 'a', encoding='utf-8') as f:
                f.write(f"{file_hash}\n")
            print(f"[L1-HASH] Added to blacklist: {file_hash[:16]}...")
        except Exception as e:
            print(f"[L1-HASH] ERROR writing to blacklist: {e}")
    
    def add_hash_to_whitelist(self, file_hash: str):
        """Add hash to local whitelist (memory + file)."""
        file_hash = file_hash.lower().strip()
        
        if file_hash in self.whitelist:
            print(f"[L1-HASH] Hash already in whitelist: {file_hash[:16]}...")
            return
        
        self.whitelist.add(file_hash)
        
        try:
            with open(self.whitelist_file, 'a', encoding='utf-8') as f:
                f.write(f"{file_hash}\n")
            print(f"[L1-HASH] Added to whitelist: {file_hash[:16]}...")
        except Exception as e:
            print(f"[L1-HASH] ERROR writing to whitelist: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive engine statistics.
        
        Returns detailed stats across all tiers for monitoring.
        """
        # Get database stats
        db_stats = self.db.get_stats()
        
        # Calculate hit rates
        total_tier1 = self.stats['tier1_whitelist_hits'] + self.stats['tier1_blacklist_hits']
        tier1_rate = (total_tier1 / max(self.stats['total_checks'], 1)) * 100
        
        tier2_rate = (self.stats['tier2_cache_hits'] / max(self.stats['total_checks'], 1)) * 100
        tier3_rate = (self.stats['tier3_api_queries'] / max(self.stats['total_checks'], 1)) * 100
        
        return {
            # Overall
            'total_checks': self.stats['total_checks'],
            'malicious_found': self.stats['malicious_found'],
            'clean_found': self.stats['clean_found'],
            'detection_rate': f"{(self.stats['malicious_found'] / max(self.stats['total_checks'], 1) * 100):.2f}%",
            
            # Tier 1
            'tier1_whitelist_hits': self.stats['tier1_whitelist_hits'],
            'tier1_blacklist_hits': self.stats['tier1_blacklist_hits'],
            'tier1_hit_rate': f"{tier1_rate:.2f}%",
            'tier1_whitelist_size': len(self.whitelist),
            'tier1_blacklist_size': len(self.blacklist),
            
            # Tier 2
            'tier2_cache_hits': self.stats['tier2_cache_hits'],
            'tier2_cache_misses': self.stats['tier2_cache_misses'],
            'tier2_hit_rate': f"{tier2_rate:.2f}%",
            'tier2_db_malicious': self.stats['tier2_db_malicious'],
            'tier2_db_clean': self.stats['tier2_db_clean'],
            'tier2_total_cached': db_stats['total_hashes'],
            
            # Tier 3
            'tier3_api_queries': self.stats['tier3_api_queries'],
            'tier3_query_rate': f"{tier3_rate:.2f}%",
            'tier3_api_malicious': self.stats['tier3_api_malicious'],
            'tier3_api_clean': self.stats['tier3_api_clean'],
            'tier3_api_errors': self.stats['tier3_api_errors'],
            'tier3_rate_limited': self.stats['tier3_rate_limited'],
            'tier3_queries_remaining': self.api_rate_limit - self.api_queries_today,
            
            # Performance
            'avg_lookup_time_ms': f"{self.stats['avg_lookup_time_ms']:.2f}",
            'fastest_lookup_ms': f"{self.stats['fastest_lookup_ms']:.2f}",
            'slowest_lookup_ms': f"{self.stats['slowest_lookup_ms']:.2f}",
        }
