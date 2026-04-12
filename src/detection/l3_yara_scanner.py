"""
Layer 3: YARA Scanner

PURPOSE:
    Scan files using YARA rules to detect malware signatures.

INPUT:
    Event dictionary (see ARCHITECTURE.md)

OUTPUT:
    - DetectionResult if YARA rule matched
    - None if no matches
"""

import os
import logging
from typing import Dict, Any, Optional, List

import yara

from src.core.pipeline import DetectionResult, ThreatLevel

logger = logging.getLogger(__name__)


class YaraScanner:
    """
    YARA rule scanning engine.

    Loads all .yar / .yara rule files from a directory, compiles them
    into a single ruleset, and scans files referenced in Sysmon events.

    INTERFACE:
        __init__(rules_dir)  – Load and compile rules from directory
        check_event(event)   – Scan files; return DetectionResult or None
        get_stats()          – Return statistics dict
    """

    # Sysmon event fields that may contain a file path worth scanning
    FILE_PATH_FIELDS = ["image", "target_filename", "parent_image"]

    def __init__(self, rules_dir: str = "config/yara_rules") -> None:
        """
        Initialise the YARA scanner.

        Walks `rules_dir` for any file ending in .yar or .yara and
        compiles them all into one combined ruleset.  If the directory
        is missing or contains no rules the scanner still starts – it
        simply returns None for every event until rules become available.

        Args:
            rules_dir: Directory (or file) containing YARA rule files.
        """
        self.rules_dir = rules_dir
        self.compiled_rules: Optional[yara.Rules] = None

        self.stats: Dict[str, Any] = {
            "total_checks": 0,
            "files_scanned": 0,
            "yara_matches": 0,
            "scan_errors": 0,
            "rules_loaded": 0,
        }

        self._load_rules()

    # ------------------------------------------------------------------
    # Rule loading
    # ------------------------------------------------------------------

    def _load_rules(self) -> None:
        """
        Discover and compile all YARA rule files under `self.rules_dir`.

        Supports both a flat directory full of .yar/.yara files and a
        single compiled rules file.  Each file is compiled individually
        and then merged so that a syntax error in one file does not
        prevent the others from loading.
        """
        rule_files = self._discover_rule_files()

        if not rule_files:
            logger.warning(
                "[L3-YARA] No rule files found in '%s'. "
                "Scanner will not detect anything until rules are added.",
                self.rules_dir,
            )
            return

        # Build a namespace dict:  {namespace: filepath}
        # Using the stem of each filename as namespace avoids conflicts.
        filepaths: Dict[str, str] = {}
        loaded = 0

        for path in rule_files:
            namespace = os.path.splitext(os.path.basename(path))[0]
            # Guard against duplicate namespaces (e.g. a.yar + a.yara)
            if namespace in filepaths:
                namespace = f"{namespace}_{loaded}"
            try:
                # Validate the individual file first
                yara.compile(filepath=path)
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
        """Return a sorted list of .yar / .yara file paths under rules_dir."""
        if not os.path.exists(self.rules_dir):
            logger.warning("[L3-YARA] Rules directory does not exist: '%s'", self.rules_dir)
            return []

        # Single file provided directly
        if os.path.isfile(self.rules_dir):
            return [self.rules_dir]

        found: List[str] = []
        for root, _dirs, files in os.walk(self.rules_dir):
            for fname in files:
                if fname.lower().endswith((".yar", ".yara")):
                    found.append(os.path.join(root, fname))

        return sorted(found)

    # ------------------------------------------------------------------
    # Detection interface
    # ------------------------------------------------------------------

    def check_event(self, event: Dict[str, Any]) -> Optional[DetectionResult]:
        """
        Scan files referenced in a Sysmon event with the compiled YARA rules.

        Steps:
            1. Increment total_checks counter.
            2. Skip early if no rules are loaded.
            3. Extract candidate file paths from the event.
            4. Scan each existing file; collect all YARA matches.
            5. Return a DetectionResult aggregating all hits, or None.

        Args:
            event: Normalised Sysmon event dictionary.

        Returns:
            DetectionResult if any YARA rule matched, None otherwise.
        """
        self.stats["total_checks"] += 1

        if self.compiled_rules is None:
            return None

        file_paths = self._extract_file_paths(event)
        if not file_paths:
            return None

        all_matches: List[yara.Match] = []
        scanned_files: List[str] = []

        for path in file_paths:
            matches = self._scan_file(path)
            if matches is not None:               # None = scan error; [] = clean
                scanned_files.append(path)
                all_matches.extend(matches)

        if not all_matches:
            return None

        self.stats["yara_matches"] += 1
        return self._build_result(all_matches, scanned_files)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_file_paths(self, event: Dict[str, Any]) -> List[str]:
        """
        Pull candidate file paths from the event dict.

        Only returns paths that actually exist on disk so we don't waste
        time calling yara.match() on missing files (common for lateral
        movement or remote events).

        Returns:
            De-duplicated list of existing file paths.
        """
        seen: set = set()
        paths: List[str] = []

        for field in self.FILE_PATH_FIELDS:
            raw = event.get(field)
            if not raw or not isinstance(raw, str):
                continue
            # Normalise Windows-style paths on Linux test environments
            path = raw.strip().strip('"')
            if path in seen:
                continue
            seen.add(path)
            if os.path.isfile(path):
                paths.append(path)
            else:
                logger.debug("[L3-YARA] File not found, skipping scan: '%s'", path)

        return paths

    def _scan_file(self, path: str,data: bytes = None) -> Optional[List[yara.Match]]:
        """
        Scan a single file and return its YARA matches.

        Returns:
            List of yara.Match objects (may be empty if clean),
            or None on error (so callers can distinguish "clean" from "failed").
        """
        try:
            self.stats["files_scanned"] += 1
            # timeout=60 guards against scanning very large / locked files
            if data is not None:
                return self.compiled_rules.match(data=data, timeout=60)
            return self.compiled_rules.match(filepath=path, timeout=60)
        except yara.TimeoutError:
            logger.warning("[L3-YARA] Scan timed out for '%s'", path)
            self.stats["scan_errors"] += 1
        except yara.Error as exc:
            logger.error("[L3-YARA] YARA error scanning '%s': %s", path, exc)
            self.stats["scan_errors"] += 1
        except PermissionError:
            logger.warning("[L3-YARA] Permission denied reading '%s'", path)
            self.stats["scan_errors"] += 1
        except OSError as exc:
            logger.error("[L3-YARA] OS error scanning '%s': %s", path, exc)
            self.stats["scan_errors"] += 1

        return None

    @staticmethod
    def _build_result(
        matches: List[yara.Match],
        scanned_files: List[str],
    ) -> DetectionResult:
        """
        Convert raw YARA match objects into a DetectionResult.

        Threat level is always CRITICAL for YARA hits – a rule match
        means a known malware signature was found on disk.

        Args:
            matches:       All yara.Match objects collected across files.
            scanned_files: Which files were actually scanned.

        Returns:
            A populated DetectionResult.
        """
        rule_names = [m.rule for m in matches]
        match_strings = [f"YARA rule: {name}" for name in rule_names]

        # Collect any tags attached to matched rules for extra context
        all_tags: List[str] = []
        for m in matches:
            all_tags.extend(m.tags)

        metadata: Dict[str, Any] = {
            "rule_names": rule_names,
            "scanned_files": scanned_files,
            # Primary scanned file kept for backward-compat with ARCHITECTURE.md
            "scanned_file": scanned_files[0] if scanned_files else "",
        }
        if all_tags:
            metadata["tags"] = list(dict.fromkeys(all_tags))  # de-dup, preserve order

        return DetectionResult(
            layer_name="L3-YARA",
            threat_level=ThreatLevel.CRITICAL,
            matches=match_strings,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Return a snapshot of scanner statistics."""
        return dict(self.stats)