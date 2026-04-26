import os
import yara
import redis
import hashlib
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Dict, Any, List, Tuple

from src.core.pipeline import DetectionResult, ThreatLevel

logger = logging.getLogger("L3-YARA")


class YaraEngine:
    """
    Layer 3 – YARA scanning engine.

    Features:
        - Loads all .yar/.yara rule files from a directory recursively
        - Scans ALL file paths referenced in a Sysmon event (not just the first)
        - Redis caching keyed by SHA256 hash (1h TTL) – skips rescanning known files
        - Parallel file scanning via ThreadPoolExecutor
        - File size guard – skips files larger than MAX_FILE_SIZE
        - Derives threat level dynamically from each rule's metadata
        - Extracts MITRE ATT&CK techniques from rule metadata
        - Graceful degradation: Redis down → caching disabled, engine keeps running
    """

    # Sysmon event fields that may reference a file on disk
    FILE_PATH_FIELDS = ["image", "target_filename", "parent_image"]

    # Files larger than this are skipped to avoid blocking the pipeline
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

    # Number of parallel threads for multi-file scanning
    MAX_WORKERS = 3

    def __init__(
        self,
        rules_dir: str = "config/yara_rules",
        redis_host: str = "localhost",
        redis_port: int = 6379,
    ) -> None:
        self.rules_dir = rules_dir
        self.compiled_rules: Optional[yara.Rules] = None

        self.LEVEL_MAPPING: Dict[str, ThreatLevel] = {
            "critical": ThreatLevel.CRITICAL,
            "high":     ThreatLevel.HIGH,
            "medium":   ThreatLevel.MEDIUM,
            "low":      ThreatLevel.LOW,
        }

        self.stats: Dict[str, Any] = {
            "total_checks":  0,
            "files_scanned": 0,
            "yara_matches":  0,
            "cache_hits":    0,
            "scan_errors":   0,
            "skipped_size":  0,
            "rules_loaded":  0,
        }

        self._load_rules()
        self.redis: Optional[redis.Redis] = self._connect_redis(redis_host, redis_port)

    # ------------------------------------------------------------------
    # Initialisation helpers
    # ------------------------------------------------------------------

    def _connect_redis(self, host: str, port: int) -> Optional[redis.Redis]:
        """Connect to Redis. Returns None silently if unavailable."""
        try:
            client = redis.Redis(host=host, port=port, db=0, decode_responses=True)
            client.ping()
            logger.info("[L3-YARA] Redis cache connected at %s:%d", host, port)
            return client
        except Exception as exc:
            logger.warning("[L3-YARA] Redis unavailable – caching disabled. Reason: %s", exc)
            return None

    def _load_rules(self) -> None:
        """Compile all .yar/.yara files found under rules_dir."""
        rule_files = self._discover_rule_files()

        if not rule_files:
            logger.warning("[L3-YARA] No rule files found in '%s'.", self.rules_dir)
            return

        filepaths: Dict[str, str] = {}
        loaded = 0

        for path in rule_files:
            namespace = os.path.splitext(os.path.basename(path))[0]
            if namespace in filepaths:
                namespace = f"{namespace}_{loaded}"
            try:
                yara.compile(filepath=path)  # validate individually first
                filepaths[namespace] = path
                loaded += 1
            except yara.SyntaxError as exc:
                logger.error("[L3-YARA] Skipping '%s' – syntax error: %s", path, exc)
            except yara.Error as exc:
                logger.error("[L3-YARA] Skipping '%s' – YARA error: %s", path, exc)

        if not filepaths:
            logger.error("[L3-YARA] All rule files failed to compile.")
            return

        try:
            self.compiled_rules = yara.compile(filepaths=filepaths)
            self.stats["rules_loaded"] = loaded
            logger.info("[L3-YARA] Loaded %d rule file(s) from '%s'.", loaded, self.rules_dir)
        except yara.Error as exc:
            logger.error("[L3-YARA] Failed to compile combined ruleset: %s", exc)

    def _discover_rule_files(self) -> List[str]:
        """Return sorted list of .yar/.yara paths under rules_dir."""
        if not os.path.exists(self.rules_dir):
            logger.warning("[L3-YARA] Rules directory not found: '%s'", self.rules_dir)
            return []

        if os.path.isfile(self.rules_dir):
            return [self.rules_dir]

        found: List[str] = []
        for root, _dirs, files in os.walk(self.rules_dir):
            for fname in files:
                if fname.lower().endswith((".yar", ".yara")):
                    found.append(os.path.join(root, fname))
        return sorted(found)

    # ------------------------------------------------------------------
    # Hashing
    # ------------------------------------------------------------------

    def _get_file_hash(self, file_path: str) -> str:
        """Return SHA256 hex digest of a file, or '' on any error."""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as exc:
            logger.debug("[L3-YARA] Could not hash '%s': %s", file_path, exc)
            return ""

    # ------------------------------------------------------------------
    # Detection interface
    # ------------------------------------------------------------------

    def check_event(self, event: Dict[str, Any]) -> Optional[DetectionResult]:
        """
        Scan all files referenced in a Sysmon event using YARA rules.

        Steps:
            1. Extract every valid file path from the event (de-duplicated).
            2. Guard each file against the size limit.
            3. Scan all files in parallel via ThreadPoolExecutor.
            4. Aggregate matches across all files into one DetectionResult.

        Returns:
            DetectionResult if any rule matched across any file, else None.
        """
        self.stats["total_checks"] += 1

        if self.compiled_rules is None:
            return None

        # 1. Collect all unique, existing file paths from the event
        file_paths = self._extract_file_paths(event)
        if not file_paths:
            return None

        per_file_results: List[DetectionResult] = []

        # 2. Single file – no thread overhead needed
        if len(file_paths) == 1:
            path = file_paths[0]
            file_hash = self._get_file_hash(path)
            if file_hash:
                result = self._scan_single_file(path, file_hash)
                if result:
                    per_file_results.append(result)

        # 3. Multiple files – scan in parallel
        else:
            tasks: List[Tuple[str, str]] = []
            for path in file_paths:
                file_hash = self._get_file_hash(path)
                if file_hash:
                    tasks.append((path, file_hash))

            with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as executor:
                futures = {
                    executor.submit(self._scan_single_file, path, fhash): path
                    for path, fhash in tasks
                }
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            per_file_results.append(result)
                    except Exception as exc:
                        logger.error(
                            "[L3-YARA] Thread error for '%s': %s",
                            futures[future], exc,
                        )

        if not per_file_results:
            return None

        self.stats["yara_matches"] += 1
        return self._aggregate_results(per_file_results)

    # ------------------------------------------------------------------
    # File path extraction
    # ------------------------------------------------------------------

    def _extract_file_paths(self, event: Dict[str, Any]) -> List[str]:
        """
        Extract all unique, existing file paths from the event dict.
        Skips files that exceed MAX_FILE_SIZE.
        """
        seen: set = set()
        paths: List[str] = []

        for field in self.FILE_PATH_FIELDS:
            raw = event.get(field)
            if not raw or not isinstance(raw, str):
                continue

            path = raw.strip().strip('"')
            if path in seen:
                continue
            seen.add(path)

            if not os.path.isfile(path):
                logger.debug("[L3-YARA] File not found, skipping: '%s'", path)
                continue

            # File size guard
            try:
                if os.path.getsize(path) > self.MAX_FILE_SIZE:
                    logger.warning(
                        "[L3-YARA] File exceeds %dMB limit, skipping: '%s'",
                        self.MAX_FILE_SIZE // (1024 * 1024), path,
                    )
                    self.stats["skipped_size"] += 1
                    continue
            except OSError:
                continue

            paths.append(path)

        return paths

    # ------------------------------------------------------------------
    # Per-file scan (cache + YARA)
    # ------------------------------------------------------------------

    def _scan_single_file(
        self, file_path: str, file_hash: str
    ) -> Optional[DetectionResult]:
        """
        Scan one file – checks Redis cache first, then runs YARA.

        Returns DetectionResult on a hit, None if clean or on error.
        """
        # Cache lookup
        if self.redis:
            try:
                cached = self.redis.get(file_hash)
                if cached:
                    self.stats["cache_hits"] += 1
                    d = json.loads(cached)
                    return DetectionResult(
                        layer_name="L3-YARA",
                        threat_level=ThreatLevel[d["level_name"]],
                        matches=d["matches"],
                        metadata=d["metadata"],
                    )
            except Exception as exc:
                logger.warning("[L3-YARA] Redis read error: %s", exc)

        # YARA scan
        try:
            self.stats["files_scanned"] += 1
            matches = self.compiled_rules.match(file_path, timeout=60)

            if not matches:
                return None

            rule_names: List[str] = [m.rule for m in matches]
            techniques: set = set()
            max_threat = ThreatLevel.LOW

            for m in matches:
                # MITRE technique from metadata (string, not list)
                technique = m.meta.get("technique", "")
                if technique:
                    techniques.add(technique)

                # Derive threat level – take the worst across all matched rules
                lvl_str  = m.meta.get("threat_level", "low").lower()
                lvl_enum = self.LEVEL_MAPPING.get(lvl_str, ThreatLevel.LOW)
                if lvl_enum.value > max_threat.value:
                    max_threat = lvl_enum

            result = DetectionResult(
                layer_name="L3-YARA",
                threat_level=max_threat,
                matches=[f"YARA rule: {name}" for name in rule_names],
                metadata={
                    "rule_names":   rule_names,
                    "scanned_file": file_path,
                    "techniques":   list(techniques),
                    "hash":         file_hash,
                },
            )

            # Store in cache
            if self.redis:
                try:
                    self.redis.set(
                        file_hash,
                        json.dumps({
                            "level_name": max_threat.name,
                            "matches":    result.matches,
                            "metadata":   result.metadata,
                        }),
                        ex=3600,  # 1 hour TTL
                    )
                except Exception as exc:
                    logger.warning("[L3-YARA] Redis write error: %s", exc)

            return result

        except yara.TimeoutError:
            logger.warning("[L3-YARA] Scan timed out for '%s'", file_path)
            self.stats["scan_errors"] += 1
        except yara.Error as exc:
            logger.error("[L3-YARA] YARA error scanning '%s': %s", file_path, exc)
            self.stats["scan_errors"] += 1
        except PermissionError:
            logger.warning("[L3-YARA] Permission denied reading '%s'", file_path)
            self.stats["scan_errors"] += 1
        except OSError as exc:
            logger.error("[L3-YARA] OS error scanning '%s': %s", file_path, exc)
            self.stats["scan_errors"] += 1

        return None

    # ------------------------------------------------------------------
    # Result aggregation
    # ------------------------------------------------------------------

    @staticmethod
    def _aggregate_results(results: List[DetectionResult]) -> DetectionResult:
        """
        Merge DetectionResult objects from multiple files into one.

        - Combines all rule names and matches
        - Takes the highest threat level across all files
        - Unions all MITRE techniques
        - Collects all scanned file paths and hashes
        """
        all_rule_names: List[str]      = []
        all_matches:    List[str]      = []
        all_techniques: set            = set()
        all_scanned:    List[str]      = []
        all_hashes:     Dict[str, str] = {}
        max_threat = ThreatLevel.LOW

        for r in results:
            all_rule_names.extend(r.metadata.get("rule_names", []))
            all_matches.extend(r.matches)
            all_techniques.update(r.metadata.get("techniques", []))
            all_scanned.append(r.metadata.get("scanned_file", ""))
            all_hashes[r.metadata.get("scanned_file", "")] = r.metadata.get("hash", "")

            if r.threat_level.value > max_threat.value:
                max_threat = r.threat_level

        return DetectionResult(
            layer_name="L3-YARA",
            threat_level=max_threat,
            matches=all_matches,
            metadata={
                "rule_names":    all_rule_names,
                "scanned_files": all_scanned,
                "scanned_file":  all_scanned[0] if all_scanned else "",  # backward compat
                "techniques":    list(all_techniques),
                "hashes":        all_hashes,
            },
        )

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Return a snapshot of scanner statistics."""
        return dict(self.stats)