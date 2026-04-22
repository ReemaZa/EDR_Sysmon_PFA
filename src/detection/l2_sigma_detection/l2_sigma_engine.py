import os
import sys
import json
import hashlib
import traceback
from typing import Dict, Any, Optional

import redis
from sigma.collection import SigmaCollection
from sigma.pipelines.sysmon import sysmon_pipeline

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))
from Enums.severity import SCORE_TO_THREAT, SEVERITY_MAP
from sigma_rule_matcher_local.matcher import RuleMatcher
from src.core.utils import DetectionResult, ThreatLevel


# ================= REDIS CONFIG =================
REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_DB = 0
SYSTEM_FINDINGS_INIT_KEY = "system:findings:initialized"

event_id_to_folders = {
    1: {'process_creation': ['process_creation']},
    2: {'file': ['file_change']},
    3: {'network_connection': ['network_connection']},
    4: {'sysmon': ['sysmon_service_change']},
    5: {'process_termination': ['process_termination']},
    6: {'driver_load': ['driver_load']},
    7: {'image_load': ['image_load']},
    8: {'create_remote_thread': ['create_remote_thread']},
    10: {'process_access': ['process_access']},
    11: {'file_event': ['file_event']},
    12: {'registry': ['registry_add', 'registry_delete', 'registry_event']},
    13: {'registry': ['registry_set', 'registry_event']},
    14: {'registry': ['registry_rename', 'registry_event']},
    15: {'create_stream_hash': ['create_stream_hash']},
    17: {'pipe_created': ['pipe_created']},
    18: {'pipe_created': ['pipe_created']},
    22: {'dns_query': ['dns_query']},
    23: {'file': ['file_delete']},
}


class SigmaEngine:

    def __init__(self, rules_dir: str = None):
        # Resolve default rules directory relative to this file so loading
        # works regardless of current working directory when the app runs.
        if rules_dir is None:
            base_dir = os.path.dirname(__file__)
            rules_dir = os.path.join(base_dir, 'rules', 'windows')
        self.rules_dir = rules_dir
        self.preloaded_rules = {}
        self.fields_by_event = {}

        self.redis = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            decode_responses=True,
            socket_connect_timeout=5,
            retry_on_timeout=True,
        )
        print(self.redis.ping())

        print("[INIT] Loading Sigma rules...")
        self.pipeline_sysmon = sysmon_pipeline()
        self._load_all_rules()

        print("[INIT] Extracting fields...")
        self.fields_by_event = self._load_fields_from_json("fields.json")

    # ================= LOAD RULES =================
    def _load_rules_from_path(self, folder_path, categories=None):
        rules = []

        if not os.path.exists(folder_path):
            return rules

        for filename in os.listdir(folder_path):
            path = os.path.join(folder_path, filename)

            if os.path.isfile(path) and path.endswith((".yml", ".yaml")):
                with open(path, "r", encoding="utf-8") as f:
                    ruleset = SigmaCollection.from_yaml(f.read())

                for rule in ruleset:
                    transformed = self.pipeline_sysmon.apply(rule)
                    rules.append(RuleMatcher(transformed))

        return rules

    def _load_all_rules(self):
        redis_initialized = False

        if self.redis.exists(SYSTEM_FINDINGS_INIT_KEY):
            redis_initialized = True
            print("[INIT] Redis findings already initialized")

        print("[INIT] Preloading findings ...")

        total_rules = 0

        for event_id, folders in event_id_to_folders.items():
            self.preloaded_rules[event_id] = []

            for folder, categories in folders.items():
                path = os.path.join(self.rules_dir, folder)
                rules = self._load_rules_from_path(path, categories)

                for matcher in rules:
                    rule = matcher.rule
                    self.preloaded_rules[event_id].append(matcher)

                    if not redis_initialized:
                        rule_id = str(getattr(rule, "id", None))
                        if not rule_id:
                            continue

                        level = str(getattr(rule, "level", "low")).lower()
                        score = SEVERITY_MAP.get(level, 0)

                        techniques = []
                        tactics = []

                        for tag in getattr(rule, "tags", []):
                            tag = str(tag)
                            if tag.startswith("attack.t"):
                                techniques.append(tag)
                            elif tag.startswith("attack."):
                                tactic = tag.replace("attack.", "")
                                if not tactic.startswith("t"):
                                    tactics.append(tactic)

                        finding_template = {
                            "rule_id": rule_id,
                            "title": rule.title,
                            "score": score,
                            "techniques": list(set(techniques)),
                            "tactics": list(set(tactics))
                        }

                        self.redis.set(
                            f"finding:{rule_id}",
                            json.dumps(finding_template)
                        )

                        total_rules += 1

        self.redis.set(SYSTEM_FINDINGS_INIT_KEY, "1")
        print(f"[INIT] Findings cached in Redis: {total_rules} rules")

    # ================= FIELD EXTRACTION =================
    def _extract_fields_recursive(self, detection, fields_set):
        for item in detection.detection_items:
            if hasattr(item, "detection_items"):
                self._extract_fields_recursive(item, fields_set)
            else:
                if getattr(item, "field", None):
                    fields_set.add(item.field)

    def _load_fields_from_json(self, path: str) -> Dict[int, Dict[str, Any]]:
        if not os.path.exists(path):
            raise FileNotFoundError(f"[ERROR] fields.json not found at {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        normalized = {}

        for event_id, content in data.items():
            try:
                eid = int(event_id)
                fields = content.get("fields", [])
                normalized[eid] = {"fields": fields}
            except Exception:
                print(f"[WARNING] Invalid event_id in fields.json: {event_id}")

        return normalized

    def export_event_fields(self):
        result = {}

        for event_id, matchers in self.preloaded_rules.items():
            fields_set = set()

            for matcher in matchers:
                rule = matcher.rule

                for f in getattr(rule, "fields", []) or []:
                    fields_set.add(f)

                try:
                    for det in rule.detection.detections.values():
                        self._extract_fields_recursive(det, fields_set)
                except:
                    pass

            result[event_id] = {"fields": list(fields_set)}

        return result

    # ================= HASH =================
    def build_event_hash(self, event: Dict[str, Any]) -> Optional[str]:
        event_id = int(event.get("event_id", -1))
        fields = self.fields_by_event.get(event_id, {}).get("fields", [])

        if not fields:
            return None

        extracted = {}

        for f in fields:
            v = event.get(f)
            if v is not None:
                extracted[f] = str(v).lower()

        canonical = json.dumps(extracted, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()

    # ================= REDIS =================
    def is_duplicate(self, event_hash: str) -> bool:
        return self.redis.exists(f"event:{event_hash}")

    def store_event(self, event_hash: str, data: dict):
        # Single unified key: event:{hash}
        self.redis.set(f"event:{event_hash}", json.dumps(data))

    def get_event(self, event_hash: str):
        data = self.redis.get(f"event:{event_hash}")
        return json.loads(data) if data else None

    def _build_aggregation_from_matched_rules(
        self,
        matched_rule_ids: list,
        matched_rule_titles: list,
        techniques: list,
        tactics: list,
        total_score: int,
        count: int,
        event: dict,
    ) -> dict:
        return {
            "event": event,
            "matches": matched_rule_titles,
            "finding_ids": matched_rule_ids,
            "total_score": total_score,
            "techniques": list(set(techniques)),
            "tactics": list(set(tactics)),
            "count": count,
        }
    def _build_graph_detection(self, data: dict) -> dict:
        """
        Convert internal aggregation → GraphBuilder format
        """
        return {
            "finding_ids": data.get("finding_ids", []),
            "techniques": data.get("techniques", []),
            "tactics": data.get("tactics", []),
            "total_score": data.get("total_score", 0),
        }
    # ================= MAIN =================
    def check_event(self, event: Dict[str, Any]) -> Optional[DetectionResult]:
        try:
            event = {**event, **event["data"]}

            event_hash = self.build_event_hash(event)
            if not event_hash:
                return None

            # ================= DUPLICATE =================
            if self.is_duplicate(event_hash):
                data = self.get_event(event_hash)

                if not data:
                    return None

                # Increment counter and persist
                data["count"] = data.get("count", 1) + 1
                self.store_event(event_hash, data)

                print(f"[DUPLICATE x{data['count']}] {event_hash}")

                # Only emit a result if the original event actually matched rules
                if data.get("matches"):
                    return DetectionResult(
                        layer_name="L2-Sigma",
                        threat_level=SCORE_TO_THREAT.get(
                            data.get("total_score", 0), ThreatLevel.LOW
                        ),
                        matches=data["matches"],
                        metadata={
                            "rules": data["matches"],
                            #"techniques": data.get("techniques", []),
                            #"tactics": data.get("tactics", []),
                            #"finding_ids": data.get("finding_ids", []),
                            #"total_score": data.get("total_score", 0),
                            "count": data["count"],
                            "source": "redis-cache",
                            "graph_detection": self._build_graph_detection(data)  # ✅ ADD THIS
                        },
                    )

                return None

            # ================= FIRST TIME — run ALL matchers first =================
            matched_rule_ids = []
            matched_rule_titles = []
            techniques = set()
            tactics = set()
            total_score = 0

            for matcher in self.preloaded_rules.get(int(event["event_id"]), []):
                if matcher.match(event):
                    rule = matcher.rule
                    rule_id = str(getattr(rule, "id", "unknown"))
                    print(f"========================id================== {rule_id}")

                    matched_rule_ids.append(rule_id)
                    matched_rule_titles.append(rule.title)

                    # Score
                    level = str(getattr(rule, "level", "low")).lower()
                    total_score += SEVERITY_MAP.get(level, 0)

                    # MITRE tags
                    for tag in getattr(rule, "tags", []):
                        tag = str(tag)
                        if tag.startswith("attack.t"):
                            techniques.add(tag)
                        elif tag.startswith("attack."):
                            tactics.add(tag.replace("attack.", ""))

            # ================= STORE — single unified record =================
            data = self._build_aggregation_from_matched_rules(
                matched_rule_ids=matched_rule_ids,
                matched_rule_titles=matched_rule_titles,
                techniques=list(techniques),
                tactics=list(tactics),
                total_score=total_score,
                count=1,
                event=event,
            )

            self.store_event(event_hash, data)
            print(f"[NEW] {event_hash}")

            if not matched_rule_titles:
                return None

            threat_level = SCORE_TO_THREAT.get(data["total_score"], ThreatLevel.LOW)

            return DetectionResult(
                layer_name="L2-Sigma",
                threat_level=threat_level,
                matches=matched_rule_titles,
                metadata={
                    "rules": matched_rule_titles,
                    #"techniques": data["techniques"],
                    #"tactics": data["tactics"],
                    #"finding_ids": matched_rule_ids,
                    #"total_score": data["total_score"],
                    "count": 1,
                    "source": "fresh-detection",
                    "graph_detection": self._build_graph_detection(data)  # ✅ ADD THIS
                },
            )

        except Exception:
            traceback.print_exc()
            return None