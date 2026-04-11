"""
SQLite Hash Cache Database Manager

PURPOSE:
    - Store hash lookup results to avoid repeated API calls
    - Cache MalwareBazaar offline database (1-2M hashes)
    - Track hash reputation over time
    - Work 100% offline after initial setup

DATABASE SCHEMA:
    hash_cache table:
        - hash (TEXT PRIMARY KEY): The file hash (SHA256/MD5/SHA1)
        - verdict (TEXT): 'malicious', 'clean', 'unknown'
        - source (TEXT): Where we got the info (blacklist/whitelist/malwarebazaar/api)
        - confidence (REAL): 0.0-1.0 confidence score
        - first_seen (TIMESTAMP): When first checked
        - last_checked (TIMESTAMP): Last lookup time
        - metadata (TEXT): JSON with extra info (signatures, file type, etc.)
        - ttl_hours (INTEGER): How long to cache (24h for clean, 168h for malicious)

INDEXES:
    - Primary key on hash (for fast lookups)
    - Index on last_checked (for cache expiration)
    - Index on verdict (for statistics)
"""
import sqlite3
import json
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from pathlib import Path


class HashCacheDB:
    """
    SQLite database for caching hash lookups and storing MalwareBazaar data.
    
    WORKFLOW:
    1. Initialize DB and create tables
    2. Check if hash exists and is not expired
    3. Return cached result or None
    4. Store new results with TTL
    """
    
    def __init__(self, db_path: str = "data/hash_cache.db"):
        """
        Initialize database connection and create tables.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Connect to database
        self.conn = sqlite3.Connection(str(self.db_path))
        self.conn.row_factory = sqlite3.Row  # Return rows as dictionaries
        
        # Create tables if they don't exist
        self._create_tables()
        
        print(f"[HASH-CACHE] Database initialized: {self.db_path}")
        print(f"[HASH-CACHE] Total cached hashes: {self.count_hashes()}")
    
    def _create_tables(self):
        """Create database schema if tables don't exist."""
        cursor = self.conn.cursor()
        
        # Main hash cache table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hash_cache (
                hash TEXT PRIMARY KEY,           -- File hash (lowercase)
                verdict TEXT NOT NULL,           -- malicious/clean/unknown
                source TEXT NOT NULL,            -- blacklist/whitelist/malwarebazaar/api
                confidence REAL DEFAULT 1.0,     -- 0.0-1.0 confidence score
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                metadata TEXT,                   -- JSON with extra info
                ttl_hours INTEGER DEFAULT 24     -- Cache duration in hours
            )
        """)
        
        # Index for fast lookups
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_last_checked 
            ON hash_cache(last_checked)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_verdict 
            ON hash_cache(verdict)
        """)
        
        self.conn.commit()
        print("[HASH-CACHE] Database schema initialized")
    
    def get_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """
        Get cached hash result if it exists and is not expired.
        
        LOGIC:
        - If hash not in DB → Return None
        - If hash expired (TTL exceeded) → Delete and return None
        - If hash valid → Return cached result
        
        Args:
            file_hash: Hash to lookup (will be lowercased)
        
        Returns:
            Dictionary with hash info, or None if not found/expired
            {
                'hash': 'abc123...',
                'verdict': 'malicious',
                'source': 'malwarebazaar',
                'confidence': 0.95,
                'first_seen': '2024-01-15 10:30:00',
                'last_checked': '2024-01-15 10:30:00',
                'metadata': {...},
                'is_expired': False
            }
        """
        file_hash = file_hash.lower().strip()
        
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM hash_cache WHERE hash = ?
        """, (file_hash,))
        
        row = cursor.fetchone()
        
        if not row:
            return None
        
        # Convert row to dictionary
        result = dict(row)
        
        # Parse metadata JSON
        if result['metadata']:
            try:
                result['metadata'] = json.loads(result['metadata'])
            except:
                result['metadata'] = {}
        
        # Check if expired
        last_checked = datetime.fromisoformat(result['last_checked'])
        ttl = timedelta(hours=result['ttl_hours'])
        expiry_time = last_checked + ttl
        
        if datetime.now() > expiry_time:
            # Expired - delete from cache
            self._delete_hash(file_hash)
            return None
        
        result['is_expired'] = False
        return result
    
    def add_hash(self, file_hash: str, verdict: str, source: str, 
                 confidence: float = 1.0, metadata: Dict = None, ttl_hours: int = None):
        """
        Add or update a hash in the cache.
        
        TTL STRATEGY:
        - Malicious: 168 hours (7 days) - threats stay threats
        - Clean: 24 hours (1 day) - re-check in case flagged later
        - Unknown: 6 hours - might appear in next MalwareBazaar dump
        
        Args:
            file_hash: Hash to cache
            verdict: 'malicious', 'clean', or 'unknown'
            source: Where info came from (blacklist/malwarebazaar/api/etc)
            confidence: 0.0-1.0 confidence score
            metadata: Extra information (dict)
            ttl_hours: Custom TTL, or use defaults based on verdict
        """
        file_hash = file_hash.lower().strip()
        
        # Default TTL based on verdict
        if ttl_hours is None:
            if verdict == 'malicious':
                ttl_hours = 168  # 7 days
            elif verdict == 'clean':
                ttl_hours = 24   # 1 day
            else:  # unknown
                ttl_hours = 6    # 6 hours
        
        # Convert metadata to JSON
        metadata_json = json.dumps(metadata) if metadata else None
        
        cursor = self.conn.cursor()
        
        # Insert or replace (upsert)
        cursor.execute("""
            INSERT OR REPLACE INTO hash_cache 
            (hash, verdict, source, confidence, first_seen, last_checked, metadata, ttl_hours)
            VALUES (
                ?,
                ?,
                ?,
                ?,
                COALESCE((SELECT first_seen FROM hash_cache WHERE hash = ?), CURRENT_TIMESTAMP),
                CURRENT_TIMESTAMP,
                ?,
                ?
            )
        """, (file_hash, verdict, source, confidence, file_hash, metadata_json, ttl_hours))
        
        self.conn.commit()
    
    def _delete_hash(self, file_hash: str):
        """Delete expired hash from cache."""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM hash_cache WHERE hash = ?", (file_hash,))
        self.conn.commit()
    
    def bulk_insert(self, hashes: List[Dict[str, Any]], batch_size: int = 1000):
        """
        Bulk insert hashes (for MalwareBazaar import).
        
        MUCH FASTER than individual inserts for large datasets.
        
        Args:
            hashes: List of dicts with hash info
                [{'hash': 'abc', 'verdict': 'malicious', 'source': 'mb', ...}, ...]
            batch_size: Number of records per transaction
        """
        cursor = self.conn.cursor()
        
        for i in range(0, len(hashes), batch_size):
            batch = hashes[i:i + batch_size]
            
            for h in batch:
                metadata_json = json.dumps(h.get('metadata', {}))
                
                cursor.execute("""
                    INSERT OR IGNORE INTO hash_cache 
                    (hash, verdict, source, confidence, metadata, ttl_hours)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    h['hash'].lower(),
                    h.get('verdict', 'malicious'),
                    h.get('source', 'malwarebazaar'),
                    h.get('confidence', 1.0),
                    metadata_json,
                    h.get('ttl_hours', 168)  # 7 days for malware
                ))
            
            self.conn.commit()
            print(f"[HASH-CACHE] Imported {min(i + batch_size, len(hashes))}/{len(hashes)} hashes")
    
    def cleanup_expired(self):
        """Remove all expired entries from cache."""
        cursor = self.conn.cursor()
        
        # Delete entries where (last_checked + ttl) < now
        cursor.execute("""
            DELETE FROM hash_cache 
            WHERE datetime(last_checked, '+' || ttl_hours || ' hours') < datetime('now')
        """)
        
        deleted = cursor.rowcount
        self.conn.commit()
        
        print(f"[HASH-CACHE] Cleaned up {deleted} expired entries")
        return deleted
    
    def count_hashes(self) -> int:
        """Get total number of cached hashes."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM hash_cache")
        return cursor.fetchone()[0]
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get database statistics.
        
        Returns:
            {
                'total_hashes': 1500000,
                'malicious': 1200000,
                'clean': 250000,
                'unknown': 50000,
                'by_source': {
                    'malwarebazaar': 1200000,
                    'blacklist': 500,
                    'api': 1000
                },
                'oldest_entry': '2024-01-01 10:00:00',
                'newest_entry': '2024-01-15 10:00:00'
            }
        """
        cursor = self.conn.cursor()
        
        # Total counts by verdict
        cursor.execute("""
            SELECT verdict, COUNT(*) as count 
            FROM hash_cache 
            GROUP BY verdict
        """)
        
        verdict_counts = {row['verdict']: row['count'] for row in cursor.fetchall()}
        
        # Counts by source
        cursor.execute("""
            SELECT source, COUNT(*) as count 
            FROM hash_cache 
            GROUP BY source
        """)
        
        source_counts = {row['source']: row['count'] for row in cursor.fetchall()}
        
        # Date ranges
        cursor.execute("""
            SELECT 
                MIN(first_seen) as oldest,
                MAX(first_seen) as newest
            FROM hash_cache
        """)
        
        dates = cursor.fetchone()
        
        return {
            'total_hashes': self.count_hashes(),
            'malicious': verdict_counts.get('malicious', 0),
            'clean': verdict_counts.get('clean', 0),
            'unknown': verdict_counts.get('unknown', 0),
            'by_source': source_counts,
            'oldest_entry': dates['oldest'] if dates['oldest'] else None,
            'newest_entry': dates['newest'] if dates['newest'] else None
        }
    
    def close(self):
        """Close database connection."""
        self.conn.close()
    
    def __del__(self):
        """Cleanup on deletion."""
        try:
            self.conn.close()
        except:
            pass
