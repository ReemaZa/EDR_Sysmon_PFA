"""
Layer 1: Hash Reputation Detection Engine (SIMPLIFIED - Local File Only)

PURPOSE:
    Check if file hashes appear in a local blacklist file.
    - Hash in blacklist → CRITICAL threat
    - Hash NOT in blacklist → Clean (return None)

INPUT:
    Event dictionary with hash fields
    
OUTPUT:
    - DetectionResult object if malicious hash found
    - None if hash is clean or no hash in event

EXAMPLE INPUT:
    event = {
        'event_id': 1,
        'event_type': 'ProcessCreate',
        'hashes': 'SHA256=abc123...,MD5=def456...',
        'image': 'C:\\malware.exe'
    }

EXAMPLE OUTPUT (if malicious):
    DetectionResult(
        layer_name="L1-Hash",
        threat_level=ThreatLevel.CRITICAL,
        matches=["Hash abc123... found in blacklist"],
        metadata={'blacklisted_hashes': ['abc123...'], 'file_path': 'C:\\malware.exe'}
    )

EXAMPLE OUTPUT (if clean):
    None
"""
import os
from typing import Dict, Any, Optional, Set, List
from pathlib import Path

# Import classes from pipeline
from src.core.utils import DetectionResult, ThreatLevel


class HashReputationEngine:
    """
    Simple hash checker using local blacklist file.
    
    HOW IT WORKS:
    1. Load malicious hashes from text file (one per line)
    2. When event arrives, extract all hashes
    3. Check if any hash is in blacklist
    4. If yes → Return DetectionResult
    5. If no → Return None
    """
    
    def __init__(self, blacklist_file: str = "config/ioc/hash_blacklist.txt"):
        """
        Initialize engine and load blacklist.
        
        Args:
            blacklist_file: Path to text file with malicious hashes
        """
        self.blacklist_file = Path(blacklist_file)
        self.blacklist: Set[str] = set()  # Set of lowercase hash strings
        
        # Statistics
        self.stats = {
            'total_checks': 0,      # How many events checked
            'blacklist_hits': 0,    # How many malicious hashes found
        }
        
        # Load blacklist from file
        self._load_blacklist()
        
        print(f"[L1-HASH] Engine initialized")
        print(f"[L1-HASH] Blacklist size: {len(self.blacklist)} hashes")
    
    def _load_blacklist(self):
        """
        Load hash blacklist from file.
        
        FILE FORMAT (hash_blacklist.txt):
            # Comments start with #
            abc123def456...  (one hash per line, any format: MD5/SHA1/SHA256)
            098f6bcd4621d373cade4e832627b4f6
            5d41402abc4b2a76b9719d911017c592
        """
        try:
            # Create file if doesn't exist
            if not self.blacklist_file.exists():
                self.blacklist_file.parent.mkdir(parents=True, exist_ok=True)
                self.blacklist_file.touch()
                print(f"[L1-HASH] Created empty blacklist: {self.blacklist_file}")
                return
            
            # Read hashes line by line
            with open(self.blacklist_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip().lower()
                    # Skip comments and empty lines
                    if line and not line.startswith('#'):
                        self.blacklist.add(line)
            
            print(f"[L1-HASH] Loaded {len(self.blacklist)} hashes from blacklist")
            
        except Exception as e:
            print(f"[L1-HASH] ERROR loading blacklist: {e}")
    
    def _extract_hashes_from_event(self, event: Dict[str, Any]) -> List[str]:
        """
        Extract all file hashes from a Sysmon event.
        
        WHAT IT LOOKS FOR:
        1. 'hashes' field → "SHA256=ABC,MD5=DEF" (from Event ID 1)
        2. Individual fields → 'md5', 'sha1', 'sha256'
        
        INPUT:
            event = {
                'event_id': 1,
                'hashes': 'SHA256=abc123,MD5=def456',
                'sha256': 'abc123',
                'md5': 'def456'
            }
        
        OUTPUT:
            ['abc123', 'def456']  # Lowercase, no duplicates
        
        Args:
            event: Sysmon event dictionary
        
        Returns:
            List of hash strings (lowercase)
        """
        hashes = []
        
        # METHOD 1: Parse "Hashes" field (Sysmon Event ID 1)
        # Format: "SHA256=ABC123,MD5=DEF456,SHA1=GHI789"
        if 'hashes' in event:
            hash_str = event['hashes']
            # Split by comma
            for part in hash_str.split(','):
                if '=' in part:
                    # Extract hash value after '='
                    hash_type, hash_value = part.split('=', 1)
                    hash_value = hash_value.strip().lower()
                    # Validate length (MD5=32, SHA1=40, SHA256=64)
                    if hash_value and len(hash_value) >= 32:
                        hashes.append(hash_value)
        
        # METHOD 2: Check individual hash fields
        for field in ['md5', 'sha1', 'sha256']:
            if field in event:
                hash_val = str(event[field]).strip().lower()
                if hash_val and len(hash_val) >= 32:
                    hashes.append(hash_val)
        
        # Remove duplicates (if hash appears in both 'hashes' and individual fields)
        return list(set(hashes))
    
    def check_event(self, event: Dict[str, Any]) -> Optional[DetectionResult]:
        """
        Check if event contains any blacklisted hashes.
        
        PROCESS:
        1. Extract all hashes from event
        2. Check each hash against blacklist
        3. If ANY hash is blacklisted → Return DetectionResult
        4. If ALL hashes are clean → Return None
        
        INPUT (event dict):
            {
                'event_id': 1,
                'event_type': 'ProcessCreate',
                'event_record_id': 12345,
                'image': 'C:\\malware.exe',
                'hashes': 'SHA256=abc123...'
            }
        
        OUTPUT (if malicious):
            DetectionResult(
                layer_name="L1-Hash",
                threat_level=ThreatLevel.CRITICAL,
                matches=["Hash abc123... in blacklist"],
                metadata={
                    'blacklisted_hashes': ['abc123...'],
                    'file_path': 'C:\\malware.exe'
                }
            )
        
        OUTPUT (if clean):
            None
        
        Args:
            event: Normalized Sysmon event dictionary
        
        Returns:
            DetectionResult if malicious, None if clean
        """
        # Update statistics
        self.stats['total_checks'] += 1
        
        # Step 1: Extract all hashes from event
        hashes = self._extract_hashes_from_event(event)
        
        # No hashes to check
        if not hashes:
            return None
        
        # Step 2: Check each hash against blacklist
        malicious_hashes = []
        for file_hash in hashes:
            if file_hash in self.blacklist:
                malicious_hashes.append(file_hash)
                self.stats['blacklist_hits'] += 1
        
        # Step 3: If malicious hashes found, create result
        if malicious_hashes:
            # Get file path for metadata (if available)
            file_path = event.get('image') or event.get('target_filename') or 'unknown'
            
            # Create list of what was detected
            matches = []
            for h in malicious_hashes:
                # Show first 16 chars of hash
                short_hash = h[:16] + "..." if len(h) > 16 else h
                matches.append(f"Hash {short_hash} found in blacklist")
            
            # Return detection result
            return DetectionResult(
                layer_name="L1-Hash",
                threat_level=ThreatLevel.CRITICAL,
                matches=matches,
                metadata={
                    'blacklisted_hashes': malicious_hashes,
                    'file_path': file_path
                }
            )
        
        # Step 4: All hashes are clean
        return None
    
    def add_hash_to_blacklist(self, file_hash: str):
        """
        Add a new hash to the blacklist (both memory and file).
        
        Args:
            file_hash: Hash to add (will be lowercased)
        """
        file_hash = file_hash.lower().strip()
        
        # Already in blacklist
        if file_hash in self.blacklist:
            print(f"[L1-HASH] Hash already in blacklist: {file_hash[:16]}...")
            return
        
        # Add to memory (in-RAM blacklist)
        self.blacklist.add(file_hash)
        
        # Append to file (persistent storage)
        try:
            with open(self.blacklist_file, 'a', encoding='utf-8') as f:
                f.write(f"{file_hash}\n")
            print(f"[L1-HASH] Added hash to blacklist: {file_hash[:16]}...")
        except Exception as e:
            print(f"[L1-HASH] ERROR writing to blacklist: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get engine statistics.
        
        OUTPUT FORMAT:
            {
                'total_checks': 100,      # Events checked
                'blacklist_hits': 5,      # Malicious hashes found
                'blacklist_size': 50      # Total hashes in blacklist
            }
        
        Returns:
            Dictionary with statistics
        """
        return {
            'total_checks': self.stats['total_checks'],
            'blacklist_hits': self.stats['blacklist_hits'],
            'blacklist_size': len(self.blacklist)
        }
