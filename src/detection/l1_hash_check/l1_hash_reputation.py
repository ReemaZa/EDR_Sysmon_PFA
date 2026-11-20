"""
Layer 1: Simplified Hash Reputation Engine

PURPOSE:
    Simple 2-step hash checking:
    1. Check MalwareBazaar table (local DB) → CRITICAL (malicious)
    2. Check MalwareBazaar API → CRITICAL (malicious) + add to table
    
FEATURES:
    - MalwareBazaar table for cached malware hashes (local SQLite DB)
    - Early exit on first match (no need to check all hashes)
    - Simple and fast
    - No whitelist (analyze all hashes)

PERFORMANCE:
    - MalwareBazaar table check: <10ms
    - API check: 1-5s (only for unknowns)
"""
import requests
import time
import os

from typing import Dict, Any, Optional, List
from pathlib import Path
from dotenv import load_dotenv
load_dotenv()
# Import utilities
from src.core.utils import DetectionResult, ThreatLevel, HASH_MATCH_SCORE

# Import database
from src.detection.l1_hash_check.malware_intelligence_db import MalwareIntelligenceDB


class HashReputationEngine:
    """
    Simplified hash reputation engine.
    
    WORKFLOW:
    1. Extract hashes from event
    2. For EACH hash (early exit on first match):
       a. Check MalwareBazaar table → CRITICAL if found
       b. Check MalwareBazaar API → CRITICAL if found + add to table
    3. Return CRITICAL if any hash is malicious, None otherwise
    """
    
    def __init__(self,
                 db_path: str = "data/malware_intelligence.db",
                 enable_api: bool = False,
                 api_rate_limit: int = 100):
        """
        Initialize hash reputation engine.
        
        Args:
            db_path: Path to SQLite database
            enable_api: Enable MalwareBazaar API lookups
            api_rate_limit: Max API queries per day
        """
        # Database
        self.db = MalwareIntelligenceDB(db_path)
        
        # API configuration
        self.enable_api = enable_api
        self.api_rate_limit = api_rate_limit
        self.api_url = "https://mb-api.abuse.ch/api/v1/"
        
        # Get API key from environment variable (SECURE!)
        self.api_key = os.environ.get('MALWAREBAZAAR_API_KEY', '')
        
        if self.enable_api and not self.api_key:
            print("[L1-HASH] WARNING: API enabled but MALWAREBAZAAR_API_KEY not set!")
            print("[L1-HASH] Set environment variable: export MALWAREBAZAAR_API_KEY='your-key'")
            self.enable_api = False
        
        # (process guid, hash) pairs already scored in the graph. A known-malware
        # hash is worth HASH_MATCH_SCORE once per process: repeated events (e.g. the
        # same DLL loaded again) must not keep inflating the score and re-triggering
        # the LLM analyst.
        self._scored_pairs = set()
        self._scored_pairs_max = 100_000

        # API rate limiting
        self.api_queries_today = 0
        self.api_reset_time = time.time() + 86400  # Reset after 24h
        
        # Statistics
        self.stats = {
            'total_checks': 0,
            'malicious_found': 0,
            'clean_found': 0,
            'malware_table_hits': 0,
            'api_queries': 0,
            'api_malicious': 0,
            'api_errors': 0,
            'api_rate_limited': 0,
        }
        
        # Get DB stats
        db_stats = self.db.get_stats()
        
        print(f"[L1-HASH] Hash reputation engine initialized")
        print(f"[L1-HASH] MalwareBazaar: {db_stats['malware_count']:,} hashes")
        print(f"[L1-HASH] API: {'Enabled' if enable_api else 'Disabled'}")
    
    def _extract_hashes_from_event(self, event: Dict[str, Any]) -> List[str]:
        """
        Extract ONLY SHA256 hashes from Sysmon event.
        Enforcing length 64 ensures we don't waste DB lookups on MD5 or SHA1.
        """
        hashes = []
        nested_hashes = event.get('hashes', {})
        
        # 1. Handle dictionary format (Already parsed)
        if isinstance(nested_hashes, dict):
            # We specifically look for the 'sha256' key for speed
            if 'sha256' in nested_hashes:
                val = str(nested_hashes['sha256']).strip().lower()
                if len(val) == 64:
                    hashes.append(val)
            else:
                # Fallback: check all values in the dict for 64-char strings
                for val in nested_hashes.values():
                    clean_val = str(val).strip().lower()
                    if len(clean_val) == 64:
                        hashes.append(clean_val)
        
        # 2. Handle string format (Raw Sysmon string like "MD5=...,SHA256=...")
        elif isinstance(nested_hashes, str):
            for part in nested_hashes.split(','):
                if 'sha256=' in part.lower():
                    _, hash_value = part.split('=', 1)
                    hash_value = hash_value.strip().lower()
                    if len(hash_value) == 64:
                        hashes.append(hash_value)
        
        return list(set(hashes))
    
    def _check_api(self, file_hash: str) -> Optional[Dict[str, Any]]:
        
        """
        Query MalwareBazaar API.
        
        If malicious, automatically adds to database.
        
        Returns:
            Dict with malware info if found, None otherwise
        """
        print(f"[L1-HASH] Checking API for hash: {file_hash[:10]}...")
        if not self.enable_api:
            print("[L1-HASH] API lookup skipped (disabled)")
            return None
        
        # Check rate limit
        if time.time() > self.api_reset_time:
            print("[L1-HASH] API rate limit reset")
            # Reset daily counter
            self.api_queries_today = 0
            self.api_reset_time = time.time() + 86400
        
        if self.api_queries_today >= self.api_rate_limit:
            print("[L1-HASH] API rate limit reached, skipping API check")
            self.stats['api_rate_limited'] += 1
            return None
        
        try:
            self.stats['api_queries'] += 1
            self.api_queries_today += 1
            
            # Make API request
            response = requests.post(
                self.api_url,
                data={'query': 'get_info', 'hash': file_hash},
                headers={'Auth-Key': self.api_key},
                timeout=5
            )
            #print(f"[L1-HASH] API response for {response.text}")

            if response.status_code != 200:
                self.stats['api_errors'] += 1
                # ADD THESE TWO LINES TO SEE THE ERROR
                print(f"[!] API Server Error: {response.status_code}")
                print(f"[!] Response Body: {response.text}") 
                return None
            
            result = response.json()
            # Hash not found
            if result.get('query_status') == 'hash_not_found':
                return None
            
            # Hash found (malicious)
            if result.get('query_status') == 'ok' and result.get('data'):
                data = result['data'][0]
                
                # Extract info
                malware_info = {
                    'file_name': data.get('file_name'),
                    'file_type': data.get('file_type'),
                    'signature': data.get('signature'),
                    'first_seen': data.get('first_seen'),
                }
                
                # Add to database (cache for next time)
                self.db.add_malware_hash(
                    file_hash=file_hash,
                    file_name=malware_info['file_name'],
                    file_type=malware_info['file_type'],
                    signature=malware_info['signature'],
                    first_seen=malware_info['first_seen'],
                    reporter='api_lookup',
                    metadata=data
                )
                
                self.stats['api_malicious'] += 1
                return malware_info
        
        except requests.exceptions.Timeout:
            self.stats['api_errors'] += 1
        except Exception as e:
            print(f"[L1-HASH] API error: {e}")
            self.stats['api_errors'] += 1
        
        return None
    
    def check_event(self, event: Dict[str, Any]) -> Optional[DetectionResult]:
        """
        Check event for malicious hashes.
        
        EARLY EXIT: Returns as soon as we find ONE malicious hash.
        No need to check all 3 hashes if first one is malicious!
        
        Args:
            event: Normalized Sysmon event
        
        Returns:
            DetectionResult if malicious, None if clean/unknown
        """
        self.stats['total_checks'] += 1
        
        # Extract hashes
        hashes = self._extract_hashes_from_event(event)
        print(f"[L1-HASH] Checking event {event.get('event_id')} with hashes: {hashes}")
        if not hashes:
            return None
        
        # Check each hash (EARLY EXIT on first match!)
        for file_hash in hashes:
            
            # === STEP 1: Check MalwareBazaar table ===
            malware_result = self.db.is_malware(file_hash)
            print(f"DEBUG: MalwareBazaar table check for {file_hash[:10]}: {'Found' if malware_result else 'Not found'}") # ADD THIS
            if malware_result:
                self.stats['malware_table_hits'] += 1
                self.stats['malicious_found'] += 1
                
                # EARLY EXIT - Found malicious hash!
                return self._create_detection_result(
                    event, file_hash, malware_result, source="MalwareBazaar DB"
                )
            
            # === STEP 2: Check MalwareBazaar API ===
            '''api_result = self._check_api(file_hash)
            if api_result:
                self.stats['malicious_found'] += 1
                
                # EARLY EXIT - Found malicious hash!
                return self._create_detection_result(
                    event, file_hash, api_result, source="MalwareBazaar API"
                )'''
        
        # All hashes are clean or unknown
        self.stats['clean_found'] += 1
        return None
    
    def _should_award_ioc_score(self, proc_guid: Optional[str], file_hash: str) -> bool:
        """True the first time this (process, hash) pair is seen, False afterwards."""
        if not proc_guid:
            return True  # cannot dedupe without a process identity
        key = (proc_guid, file_hash)
        if key in self._scored_pairs:
            return False
        if len(self._scored_pairs) >= self._scored_pairs_max:
            self._scored_pairs.clear()  # bound memory on long-running agents
        self._scored_pairs.add(key)
        return True

    def _create_detection_result(self, event: Dict[str, Any], file_hash: str,
                                 malware_info: Dict[str, Any], source: str) -> DetectionResult:
        """
        Create a DetectionResult from malware info.
        
        Args:
            event: Original event
            file_hash: The malicious hash
            malware_info: Info from DB or API
            source: Where we found it (DB/API)
        
        Returns:
            DetectionResult with CRITICAL threat level
        """
        # Get file path from event
        file_path = event.get('image') or event.get('target_filename') or 'unknown'
        
        # Build match description
        short_hash = file_hash[:16] + "..." if len(file_hash) > 16 else file_hash
        signature = malware_info.get('signature', 'unknown')
        
        match_text = f"Hash {short_hash} ({source})"
        if signature and signature != 'unknown':
            match_text += f" - {signature}"
        
        # Graph detection: same shape as the Sigma layer's graph_detection, consumed
        # by agent.process_event -> GraphBuilder. The hash score travels in its own
        # 'ioc_score' key (total_score stays the Sigma-only score) so the graph
        # builder can attach it to the right process (see GraphBuilder._edge_params).
        event_data = event.get('data') or {}
        proc_guid = event_data.get('ProcessGuid') or event.get('guid')
        award = self._should_award_ioc_score(proc_guid, file_hash)
        ioc_label = signature if signature and signature != 'unknown' else file_hash[:16]
        graph_detection = {
            'finding_ids': [f"L1-HASH:{ioc_label}"],
            'techniques': [],
            'tactics': [],
            'total_score': 0,
            'ioc_score': HASH_MATCH_SCORE if award else 0,
        }

        # Create metadata
        metadata = {
            'malicious_hash': file_hash,
            'file_path': file_path,
            'source': source,
            'signature': signature,
            'file_name': malware_info.get('file_name'),
            'file_type': malware_info.get('file_type'),
            'first_seen': malware_info.get('first_seen'),
            'graph_detection': graph_detection,
        }
        
        return DetectionResult(
            layer_name="L1-Hash",
            threat_level=ThreatLevel.CRITICAL,
            matches=[match_text],
            metadata=metadata
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get engine statistics.
        
        Returns:
            {
                'total_checks': 1000,
                'malicious_found': 10,
                'clean_found': 990,
                'detection_rate': '1.00%',
                'malware_table_hits': 8,
                'api_queries': 2,
                'api_malicious': 2,
                'api_errors': 0,
                'api_rate_limited': 0,
                'malware_db_size': 500000,
                ...
            }
        """
        db_stats = self.db.get_stats()
        
        return {
            # Overall
            'total_checks': self.stats['total_checks'],
            'malicious_found': self.stats['malicious_found'],
            'clean_found': self.stats['clean_found'],
            'detection_rate': f"{(self.stats['malicious_found'] / max(self.stats['total_checks'], 1) * 100):.2f}%",
            
            # Detection sources
            'malware_table_hits': self.stats['malware_table_hits'],
            'api_queries': self.stats['api_queries'],
            'api_malicious': self.stats['api_malicious'],
            'api_errors': self.stats['api_errors'],
            'api_rate_limited': self.stats['api_rate_limited'],
            
            # Database stats
            'malware_db_size': db_stats['malware_count'],
        }