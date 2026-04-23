"""
graph_builder.py
================
Sysmon → Memgraph builder implementing the agreed design:

NODE STRATEGY
─────────────
• ProcessTemplate  — dedup key = sha256(image + parent_image + cmdline_pattern)
                     stores: image, parent_image, description, seen_count,
                             max_seen_score (hint only, updated when instances score)
                     NEVER deleted.

• ProcessInstance  — created ONLY when total_score > 0 (detection fired).
                     stores: guid, pid, cmdline, user, host, score, alive,
                             start_time, end_time
                     Links: INSTANCE_OF → ProcessTemplate
                            CHILD_OF    → parent ProcessInstance  (if parent exists & score>0)
                                       → parent ProcessTemplate   (fallback: parent not yet instance)

• All other nodes (File, Network, DNS, Registry, Driver, User) — always created on
  first encounter, never duplicated (MERGE on id).

EDGE STRATEGY
─────────────
Every edge carries a compressed hash so identical structural+semantic events collapse
into one edge.  timestamp is NOT part of MERGE — instead first_seen / last_seen /
count are maintained.

  edge_hash = sha256(src_id + rel_type + dst_id + finding_type_signature)

  finding_type_signature = sha256(sorted(techniques + tactics))
  This means: same pair + same alert class → same edge (count++)
              same pair + different alert   → different edge

  ON CREATE : set all fields
  ON MATCH  : update last_seen, count, max_score, append new finding_ids (capped at 20)

SCORE INHERITANCE
─────────────────
Edge weights (base contributions):
  CREATED          0.3
  CONNECTED        0.2
  INJECTED_THREAD  0.9
  ACCESSED_MEMORY  0.8
  (all others)     use detection total_score directly

When a ProcessInstance is created:
  1. Its own score = detection total_score
  2. If parent Instance exists → child.score += parent.score * 0.4
  3. When a parent Instance is created LATER, it scans children linked via
     CHILD_OF→template and updates their scores.

LATE PARENT LINKING
───────────────────
If parent had no instance when child was created, child stores
  pending_parent_template = parent_template_hash
When parent eventually becomes an instance (score > 0), GraphBuilder.link_late_children()
is called automatically, which:
  - Finds all ProcessInstances whose pending_parent_template matches
  - Creates CHILD_OF edges
  - Propagates parent score to those children
"""

import hashlib
import json
import re
import traceback
from datetime import datetime
from typing import Optional

from gqlalchemy import Memgraph

MEMGRAPH_HOST = "localhost"
MEMGRAPH_PORT = 7687

# ── Edge base weights (independent of detection score)
EDGE_WEIGHTS: dict[str, float] = {
    "CREATED":          0.3,
    "CONNECTED":        0.2,
    "INJECTED_THREAD":  0.9,
    "ACCESSED_MEMORY":  0.8,
}

# ── Score threshold: only create a ProcessInstance above this
INSTANCE_SCORE_THRESHOLD = 0.0   # > 0 means any positive detection creates instance

# ── Parent-score inheritance weight
PARENT_INHERITANCE = 0.4

# ── Max finding_ids stored per edge
FINDING_IDS_CAP = 20


# ══════════════════════════════════════════════════════════════════════════════
class GraphBuilder:

    def __init__(self):
        self.db = Memgraph(host=MEMGRAPH_HOST, port=MEMGRAPH_PORT)
        self._init_schema()

    # ──────────────────────────────────────────────────────────────────────────
    # DB HELPERS
    # ──────────────────────────────────────────────────────────────────────────

    def _run(self, query: str, params: dict = {}):
        action = "UNKNOWN"
        for kw in ("MERGE", "CREATE", "MATCH", "SET", "DELETE"):
            if kw in query.upper():
                action = kw
                break
        nodes = re.findall(r":(\w+)", query)
        rels  = re.findall(r"\[:(\w+)", query)
        try:
            self.db.execute(query, params)
            print(f"[OK]   {action} | nodes={nodes} | rels={rels}")
            return True
        except Exception as e:
            print(f"[FAIL] {action} | nodes={nodes} | rels={rels} | {e}")
            return False

    def _fetch(self, query: str, params: dict = {}) -> list[dict]:
        try:
            return list(self.db.execute_and_fetch(query, params))
        except Exception as e:
            print(f"[FETCH FAIL] {e}")
            return []

    def _init_schema(self):
        constraints = [
            "CREATE CONSTRAINT ON (n:ProcessTemplate) ASSERT n.template_hash IS UNIQUE",
            "CREATE CONSTRAINT ON (n:ProcessInstance) ASSERT n.id IS UNIQUE",
            "CREATE CONSTRAINT ON (n:File)            ASSERT n.id IS UNIQUE",
            "CREATE CONSTRAINT ON (n:Network)         ASSERT n.id IS UNIQUE",
            "CREATE CONSTRAINT ON (n:Registry)        ASSERT n.id IS UNIQUE",
            "CREATE CONSTRAINT ON (n:DNS)             ASSERT n.id IS UNIQUE",
            "CREATE CONSTRAINT ON (n:Driver)          ASSERT n.id IS UNIQUE",
            "CREATE CONSTRAINT ON (n:User)            ASSERT n.id IS UNIQUE",
        ]
        for c in constraints:
            try:
                self._run(c)
            except Exception:
                pass

    # ──────────────────────────────────────────────────────────────────────────
    # HASH HELPERS
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _now() -> str:
        return datetime.utcnow().isoformat()

    @staticmethod
    def _h(obj) -> str:
        raw = json.dumps(obj, sort_keys=True, ensure_ascii=True)
        return hashlib.sha256(raw.encode()).hexdigest()

    @classmethod
    def _template_hash(cls, image: str, parent_image: str, cmdline: str) -> str:
        """
        Template identity = (image, parent_image, cmdline).
        parent_image is baked in so powershell-from-word ≠ powershell-from-explorer.
        cmdline is normalised to its basename+flags (strip paths, keep switches).
        """
        def normalise_cmd(cmd: str) -> str:
            # keep only the exe name and flags, drop full paths and variable args
            cmd = cmd.lower().strip()
            cmd = re.sub(r"[a-z]:\\[^\s]+\\", "", cmd)   # strip paths
            cmd = re.sub(r"\s+", " ", cmd)
            return cmd[:256]                               # cap length

        return cls._h({
            "image":        (image        or "").lower(),
            "parent_image": (parent_image or "").lower(),
            "cmdline":      normalise_cmd(cmdline or ""),
        })

    @classmethod
    def _edge_hash(cls, src_id: str, rel_type: str, dst_id: str,
                   techniques: list, tactics: list) -> str:
        """
        Edge identity = (src, rel_type, dst, alert-class-signature).
        Two events that differ only in timestamp / individual finding_id
        but share the same technique+tactic set → same edge → count++.
        Two events with a different technique set → different edge.
        """
        sig = cls._h({"techniques": sorted(techniques), "tactics": sorted(tactics)})
        return cls._h({
            "src":      src_id,
            "rel":      rel_type,
            "dst":      dst_id,
            "alert_sig": sig,
        })

    @staticmethod
    def _edge_params(detection: Optional[dict]) -> dict:
        if not detection:
            return {"finding_ids": [], "techniques": [], "tactics": [], "total_score": 0.0}
        return {
            "finding_ids": detection.get("finding_ids", []),
            "techniques":  detection.get("techniques",  []),
            "tactics":     detection.get("tactics",     []),
            "total_score": float(detection.get("total_score", 0.0)),
        }

    # ──────────────────────────────────────────────────────────────────────────
    # TEMPLATE HELPERS
    # ──────────────────────────────────────────────────────────────────────────

    def _upsert_template(self, image: str, parent_image: str,
                         cmdline: str, description: str = "") -> str:
        """Always upsert a template. Returns template_hash."""
        t_hash = self._template_hash(image, parent_image, cmdline)
        self._run(
            """
            MERGE (t:ProcessTemplate {template_hash: $t_hash})
            ON CREATE SET
                t.image        = $image,
                t.parent_image = $parent_image,
                t.cmdline      = $cmdline,
                t.description  = $description,
                t.seen_count   = 1,
                t.max_seen_score = 0.0
            ON MATCH SET
                t.seen_count = t.seen_count + 1
            """,
            {
                "t_hash":       t_hash,
                "image":        (image        or "").lower(),
                "parent_image": (parent_image or "").lower(),
                "cmdline":      (cmdline      or "").lower(),
                "description":  (description  or "").lower(),
            },
        )
        return t_hash

    def _get_template_max_score(self, t_hash: str) -> float:
        rows = self._fetch(
            "MATCH (t:ProcessTemplate {template_hash: $h}) RETURN t.max_seen_score AS s",
            {"h": t_hash},
        )
        return float(rows[0]["s"]) if rows else 0.0

    def _update_template_max_score(self, t_hash: str, score: float):
        self._run(
            """
            MATCH (t:ProcessTemplate {template_hash: $h})
            SET t.max_seen_score = CASE
                WHEN $score > t.max_seen_score THEN $score
                ELSE t.max_seen_score
            END
            """,
            {"h": t_hash, "score": score},
        )

    # ──────────────────────────────────────────────────────────────────────────
    # INSTANCE HELPERS
    # ──────────────────────────────────────────────────────────────────────────

    def _instance_exists(self, guid: str) -> bool:
        rows = self._fetch(
            "MATCH (p:ProcessInstance {id: $guid}) RETURN p.id AS id",
            {"guid": guid},
        )
        return bool(rows)

    def _get_instance_score(self, guid: str) -> float:
        rows = self._fetch(
            "MATCH (p:ProcessInstance {id: $guid}) RETURN p.score AS s",
            {"guid": guid},
        )
        return float(rows[0]["s"]) if rows else 0.0

    def _create_instance(
        self,
        guid: str,
        image: str,
        parent_image: str,
        cmdline: str,
        description: str,
        user: str,
        score: float,
        t_hash: str,
        pending_parent_template: str = "",
        timestamp: str = "",
    ):
        """Create ProcessInstance node and wire INSTANCE_OF + RAN_AS."""
        ts = timestamp or self._now()
        self._run(
            """
            MERGE (p:ProcessInstance {id: $guid})
            ON CREATE SET
                p.image                   = $image,
                p.cmdline                 = $cmdline,
                p.user                    = $user,
                p.score                   = $score,
                p.alive                   = true,
                p.start_time              = $ts,
                p.pending_parent_template = $ppt
            ON MATCH SET
                p.score = CASE WHEN $score > p.score THEN $score ELSE p.score END
            """,
            {
                "guid":  guid,
                "image": (image   or "").lower(),
                "cmdline": (cmdline or "").lower(),
                "user":  (user    or "UNKNOWN"),
                "score": score,
                "ts":    ts,
                "ppt":   pending_parent_template,
            },
        )
        # INSTANCE_OF → template
        self._run(
            """
            MATCH (p:ProcessInstance   {id: $guid})
            MATCH (t:ProcessTemplate   {template_hash: $t_hash})
            MERGE (p)-[:INSTANCE_OF]->(t)
            """,
            {"guid": guid, "t_hash": t_hash},
        )
        # RAN_AS → user
        if user:
            self._run("MERGE (u:User {id: $user})", {"user": user or "UNKNOWN"})
            self._run(
                """
                MATCH (p:ProcessInstance {id: $guid})
                MATCH (u:User {id: $user})
                MERGE (p)-[:RAN_AS]->(u)
                """,
                {"guid": guid, "user": user or "UNKNOWN"},
            )
        # Update template hint
        self._update_template_max_score(t_hash, score)

    def _link_to_parent(self, child_guid: str, parent_guid: str,
                        child_score: float, parent_score: float):
        """Create CHILD_OF edge and apply parent inheritance to child."""
        self._run(
            """
            MATCH (child:ProcessInstance  {id: $child_guid})
            MATCH (parent:ProcessInstance {id: $parent_guid})
            MERGE (child)-[:CHILD_OF]->(parent)
            """,
            {"child_guid": child_guid, "parent_guid": parent_guid},
        )
        # Inherit parent score
        inherited = parent_score * PARENT_INHERITANCE
        if inherited > 0:
            self._run(
                """
                MATCH (p:ProcessInstance {id: $guid})
                SET p.score = p.score + $delta
                """,
                {"guid": child_guid, "delta": inherited},
            )

    def _link_to_parent_template(self, child_guid: str, parent_t_hash: str):
        """Fallback: parent has no instance yet — link child to parent template."""
        self._run(
            """
            MATCH (child:ProcessInstance {id: $child_guid})
            MATCH (pt:ProcessTemplate    {template_hash: $t_hash})
            MERGE (child)-[:CHILD_OF_TEMPLATE]->(pt)
            """,
            {"child_guid": child_guid, "t_hash": parent_t_hash},
        )

    def link_late_children(self, parent_guid: str):
        """
        Called after a parent ProcessInstance is created.
        Finds all ProcessInstances that stored this parent's template hash
        in pending_parent_template and had no instance parent yet.
        Wires CHILD_OF edges and propagates parent score.
        """
        rows = self._fetch(
            """
            MATCH (parent:ProcessInstance {id: $parent_guid})-[:INSTANCE_OF]->(pt:ProcessTemplate)
            RETURN pt.template_hash AS t_hash, parent.score AS pscore
            """,
            {"parent_guid": parent_guid},
        )
        if not rows:
            return
        t_hash       = rows[0]["t_hash"]
        parent_score = float(rows[0]["pscore"] or 0)

        # Find children waiting for this template
        children = self._fetch(
            """
            MATCH (child:ProcessInstance {pending_parent_template: $t_hash})
            WHERE NOT (child)-[:CHILD_OF]->(:ProcessInstance)
            RETURN child.id AS guid, child.score AS cscore
            """,
            {"t_hash": t_hash},
        )
        for c in children:
            self._link_to_parent(c["guid"], parent_guid, float(c["cscore"] or 0), parent_score)
            # Clear the pending field
            self._run(
                "MATCH (p:ProcessInstance {id: $guid}) SET p.pending_parent_template = ''",
                {"guid": c["guid"]},
            )

    def _update_process_score(self, guid: str, delta: float):
        if not guid or delta == 0:
            return
        self._run(
            """
            MATCH (p:ProcessInstance {id: $guid})
            SET p.score = coalesce(p.score, 0) + $delta
            """,
            {"guid": guid, "delta": delta},
        )

    # ──────────────────────────────────────────────────────────────────────────
    # GENERIC EDGE UPSERT
    # ──────────────────────────────────────────────────────────────────────────

    def _merge_edge(
        self,
        src_id: str,
        src_label: str,
        rel_type: str,
        dst_id: str,
        dst_label: str,
        ep: dict,
        timestamp: str,
        extra_create: dict = {},   # additional ON CREATE fields
    ):
        """
        Single universal edge upsert.
        MERGE key = edge_hash only (timestamp excluded → deduplication works).
        ON CREATE : populate all fields.
        ON MATCH  : update last_seen, count, max_score, append new finding_ids.
        """
        e_hash = self._edge_hash(src_id, rel_type, dst_id,
                                 ep["techniques"], ep["tactics"])
        base_weight = EDGE_WEIGHTS.get(rel_type, 0.0)
        effective_score = max(ep["total_score"], base_weight)

        # Build extra SET clauses for ON CREATE
        extra_sets = ""
        for k in extra_create:
            extra_sets += f", r.{k} = ${k}"

        params = {
            "src_id":    src_id,
            "dst_id":    dst_id,
            "e_hash":    e_hash,
            "ts":        timestamp,
            "fids":      ep["finding_ids"][:FINDING_IDS_CAP],
            "techs":     ep["techniques"],
            "tacs":      ep["tactics"],
            "score":     effective_score,
            **extra_create,
        }

        self._run(
            f"""
            MATCH (src:{src_label} {{id: $src_id}})
            MATCH (dst:{dst_label} {{id: $dst_id}})
            MERGE (src)-[r:{rel_type} {{edge_hash: $e_hash}}]->(dst)
            ON CREATE SET
                r.first_seen   = $ts,
                r.last_seen    = $ts,
                r.count        = 1,
                r.finding_ids  = $fids,
                r.techniques   = $techs,
                r.tactics      = $tacs,
                r.max_score    = $score
                {extra_sets}
            ON MATCH SET
                r.last_seen   = $ts,
                r.count       = r.count + 1,
                r.max_score   = CASE WHEN $score > r.max_score THEN $score ELSE r.max_score END,
                r.finding_ids = CASE
                    WHEN size(r.finding_ids) < {FINDING_IDS_CAP}
                    THEN r.finding_ids + [x IN $fids WHERE NOT x IN r.finding_ids]
                    ELSE r.finding_ids
                END
            """,
            params,
        )

    # ──────────────────────────────────────────────────────────────────────────
    # ENSURE PROCESS — lightweight: only creates template, no instance
    # ──────────────────────────────────────────────────────────────────────────

    def _ensure_process(self, event: dict, guid_key: str = "ProcessGuid") -> Optional[str]:
        """
        Returns the guid if a ProcessInstance exists.
        If it doesn't exist, returns None (caller decides whether to create it).
        Always ensures the template exists as a side-effect.
        """
        d = event if "Image" in event or "image" in event else event.get("data", event)

        guid        = d.get(guid_key) or d.get("process_guid") or d.get("ProcessGuid")
        image       = d.get("Image")       or d.get("image")       or ""
        parent_img  = d.get("ParentImage") or d.get("parent_image") or ""
        cmdline     = d.get("CommandLine") or d.get("cmdline")     or ""
        description = d.get("Description") or d.get("description") or ""

        # Always upsert template
        if image:
            self._upsert_template(image, parent_img, cmdline, description)

        if not guid:
            return None

        return guid if self._instance_exists(guid) else None

    # ──────────────────────────────────────────────────────────────────────────
    # DECIDE & CREATE INSTANCE (used by every handler)
    # ──────────────────────────────────────────────────────────────────────────

    def _get_or_create_instance(
        self,
        guid: str,
        image: str,
        parent_image: str,
        cmdline: str,
        description: str,
        user: str,
        score: float,
        parent_guid: str = "",
        timestamp: str = "",
    ) -> str:
        """
        Creates a ProcessInstance if score > threshold OR if it already exists.
        Handles parent linking (instance or template fallback).
        Returns guid if instance exists/created, else empty string.
        """
        if not guid:
            return ""

        t_hash = self._template_hash(image, parent_image, cmdline)
        # Always upsert template first
        self._upsert_template(image, parent_image, cmdline, description)

        if score <= INSTANCE_SCORE_THRESHOLD and not self._instance_exists(guid):
            # Score is zero — no instance, just template
            return ""

        # Determine pending_parent_template for late-linking
        parent_t_hash = self._template_hash(parent_image, "", "") if parent_image else ""

        self._create_instance(
            guid=guid, image=image, parent_image=parent_image,
            cmdline=cmdline, description=description, user=user,
            score=score, t_hash=t_hash,
            pending_parent_template=parent_t_hash,
            timestamp=timestamp,
        )

        # Link to parent
        if parent_guid and self._instance_exists(parent_guid):
            parent_score = self._get_instance_score(parent_guid)
            self._link_to_parent(guid, parent_guid, score, parent_score)
        elif parent_t_hash:
            self._link_to_parent_template(guid, parent_t_hash)

        # Check for late children waiting for this instance
        self.link_late_children(guid)

        return guid

    # ──────────────────────────────────────────────────────────────────────────
    # EVENT HANDLERS
    # ──────────────────────────────────────────────────────────────────────────

    def handle_event_1(self, event: dict, detection: Optional[dict] = None):
        """ProcessCreate."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        parent_guid  = d.get("ParentProcessGuid") or d.get("parent_process_guid") or ""
        child_guid   = d.get("ProcessGuid")       or d.get("process_guid")        or ""
        parent_image = d.get("ParentImage")        or ""
        child_image  = d.get("Image")              or ""
        parent_cmd   = d.get("ParentCommandLine")  or ""
        child_cmd    = d.get("CommandLine")        or ""
        description  = d.get("Description")        or ""
        user         = d.get("User")               or ""

        # ── always upsert both templates
        parent_t_hash = self._upsert_template(parent_image, "", parent_cmd)
        child_t_hash  = self._upsert_template(child_image, parent_image, child_cmd, description)

        score = ep["total_score"]

        # ── parent instance (created if it has score context from prior events)
        if parent_guid and not self._instance_exists(parent_guid) and score > INSTANCE_SCORE_THRESHOLD:
            self._get_or_create_instance(
                guid=parent_guid, image=parent_image, parent_image="",
                cmdline=parent_cmd, description="", user="",
                score=0.0,   # parent itself has no direct score here
                timestamp=ts,
            )

        # ── child instance
        child_inst = self._get_or_create_instance(
            guid=child_guid, image=child_image, parent_image=parent_image,
            cmdline=child_cmd, description=description, user=user,
            score=score, parent_guid=parent_guid, timestamp=ts,
        )

        # ── CREATED edge (instance→instance if both exist, else skip edge)
        if child_inst and parent_guid and self._instance_exists(parent_guid):
            self._merge_edge(
                src_id=parent_guid, src_label="ProcessInstance",
                rel_type="CREATED",
                dst_id=child_guid,  dst_label="ProcessInstance",
                ep=ep, timestamp=ts,
            )
            self._update_process_score(parent_guid, score * 0.3)
            self._update_process_score(child_guid,  score)

    def handle_event_2(self, event: dict, detection: Optional[dict] = None):
        """Timestomp — always suspicious, always create instance."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid    = d.get("ProcessGuid") or d.get("process_guid") or ""
        file_id = (d.get("TargetFilename") or "").lower()
        if not guid or not file_id:
            return

        inst = self._get_or_create_instance(
            guid=guid, image=d.get("Image",""), parent_image=d.get("ParentImage",""),
            cmdline=d.get("CommandLine",""), description="", user=d.get("User",""),
            score=max(ep["total_score"], 0.6),   # timestomp is always suspicious
            timestamp=ts,
        )
        if not inst:
            return

        self._run("MERGE (f:File {id: $id})", {"id": file_id})
        self._merge_edge("ProcessInstance", "ProcessInstance", "TIMESTOMPED",
                         file_id, "File", ep, ts)  # wrong order fix:
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="TIMESTOMPED",
            dst_id=file_id, dst_label="File",
            ep=ep, timestamp=ts,
        )
        self._update_process_score(guid, ep["total_score"])

    def handle_event_3(self, event: dict, detection: Optional[dict] = None):
        """NetworkConnect."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid   = d.get("ProcessGuid") or d.get("process_guid") or ""
        dst_ip = (d.get("DestinationIp") or d.get("destination_ip") or "").lower()
        if not guid or not dst_ip:
            return

        inst = self._get_or_create_instance(
            guid=guid, image=d.get("Image",""), parent_image=d.get("ParentImage",""),
            cmdline=d.get("CommandLine",""), description="", user=d.get("User",""),
            score=ep["total_score"], timestamp=ts,
        )
        if not inst:
            return

        self._run("MERGE (n:Network {id: $ip})", {"ip": dst_ip})
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="CONNECTED",
            dst_id=dst_ip, dst_label="Network",
            ep=ep, timestamp=ts,
            extra_create={
                "port":     int(d.get("DestinationPort") or 0),
                "protocol": d.get("Protocol") or "",
            },
        )
        self._update_process_score(guid, ep["total_score"])

    def handle_event_6(self, event: dict, detection: Optional[dict] = None):
        """DriverLoad."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid   = d.get("ProcessGuid") or d.get("process_guid") or ""
        sha256 = (d.get("Hashes") or "").split("SHA256=")[-1].split(",")[0].lower()
        image  = (d.get("ImageLoaded") or "").lower()
        if not guid or not sha256:
            return

        inst = self._get_or_create_instance(
            guid=guid, image=d.get("Image",""), parent_image=d.get("ParentImage",""),
            cmdline=d.get("CommandLine",""), description="", user=d.get("User",""),
            score=ep["total_score"], timestamp=ts,
        )
        if not inst:
            return

        self._run(
            "MERGE (drv:Driver {id: $sha256}) ON CREATE SET drv.image = $image",
            {"sha256": sha256, "image": image},
        )
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="LOADED_DRIVER",
            dst_id=sha256, dst_label="Driver",
            ep=ep, timestamp=ts,
        )
        self._update_process_score(guid, ep["total_score"])

    def handle_event_7(self, event: dict, detection: Optional[dict] = None):
        """ImageLoad."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid   = d.get("ProcessGuid") or d.get("process_guid") or ""
        sha256 = (d.get("Hashes") or "").split("SHA256=")[-1].split(",")[0].lower()
        image  = (d.get("ImageLoaded") or "").lower()
        if not guid or not sha256:
            return

        inst = self._get_or_create_instance(
            guid=guid, image=d.get("Image",""), parent_image=d.get("ParentImage",""),
            cmdline=d.get("CommandLine",""), description="", user=d.get("User",""),
            score=ep["total_score"], timestamp=ts,
        )
        if not inst:
            return

        self._run(
            "MERGE (img:Driver {id: $sha256}) ON CREATE SET img.image = $image",
            {"sha256": sha256, "image": image},
        )
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="LOADED_IMAGE",
            dst_id=sha256, dst_label="Driver",
            ep=ep, timestamp=ts,
        )
        self._update_process_score(guid, ep["total_score"])

    def handle_event_8(self, event: dict, detection: Optional[dict] = None):
        """CreateRemoteThread — always create both instances, always high score."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        src_guid = d.get("SourceProcessGuid") or d.get("source_process_guid") or ""
        tgt_guid = d.get("TargetProcessGuid") or d.get("target_process_guid") or ""
        if not src_guid or not tgt_guid:
            return

        forced_score = max(ep["total_score"], EDGE_WEIGHTS["INJECTED_THREAD"])

        src_inst = self._get_or_create_instance(
            guid=src_guid, image=d.get("SourceImage",""), parent_image="",
            cmdline="", description="", user="",
            score=forced_score, timestamp=ts,
        )
        tgt_inst = self._get_or_create_instance(
            guid=tgt_guid, image=d.get("TargetImage",""), parent_image="",
            cmdline="", description="", user="",
            score=forced_score, timestamp=ts,
        )
        if not src_inst or not tgt_inst:
            return

        self._merge_edge(
            src_id=src_guid, src_label="ProcessInstance",
            rel_type="INJECTED_THREAD",
            dst_id=tgt_guid, dst_label="ProcessInstance",
            ep=ep, timestamp=ts,
            extra_create={"start_function": d.get("StartFunction") or ""},
        )
        self._update_process_score(src_guid, forced_score)
        self._update_process_score(tgt_guid, forced_score)

    def handle_event_10(self, event: dict, detection: Optional[dict] = None):
        """ProcessAccess — always create both instances."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        src_guid = d.get("SourceProcessGUID") or d.get("source_guid") or ""
        tgt_guid = d.get("TargetProcessGUID") or d.get("target_guid") or ""
        if not src_guid or not tgt_guid:
            return

        forced_score = max(ep["total_score"], EDGE_WEIGHTS["ACCESSED_MEMORY"])

        src_inst = self._get_or_create_instance(
            guid=src_guid, image=d.get("SourceImage",""), parent_image="",
            cmdline="", description="", user="",
            score=forced_score, timestamp=ts,
        )
        tgt_inst = self._get_or_create_instance(
            guid=tgt_guid, image=d.get("TargetImage",""), parent_image="",
            cmdline="", description="", user="",
            score=forced_score, timestamp=ts,
        )
        if not src_inst or not tgt_inst:
            return

        self._merge_edge(
            src_id=src_guid, src_label="ProcessInstance",
            rel_type="ACCESSED_MEMORY",
            dst_id=tgt_guid, dst_label="ProcessInstance",
            ep=ep, timestamp=ts,
            extra_create={"access_mask": d.get("GrantedAccess") or ""},
        )
        self._update_process_score(src_guid, forced_score)

    def handle_event_11(self, event: dict, detection: Optional[dict] = None):
        """FileCreate."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid    = d.get("ProcessGuid") or ""
        file_id = (d.get("TargetFilename") or "").lower()
        if not guid or not file_id:
            return

        inst = self._get_or_create_instance(
            guid=guid, image=d.get("Image",""), parent_image=d.get("ParentImage",""),
            cmdline=d.get("CommandLine",""), description="", user=d.get("User",""),
            score=ep["total_score"], timestamp=ts,
        )
        if not inst:
            return

        self._run("MERGE (f:File {id: $id})", {"id": file_id})
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="CREATED_FILE",
            dst_id=file_id, dst_label="File",
            ep=ep, timestamp=ts,
            extra_create={"size": int(d.get("Size") or 0)},
        )
        self._update_process_score(guid, ep["total_score"])

    def _handle_registry(self, event: dict, event_type: str, detection: Optional[dict] = None):
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid   = d.get("ProcessGuid") or ""
        reg_id = (d.get("TargetObject") or "").lower()
        if not guid or not reg_id:
            return

        inst = self._get_or_create_instance(
            guid=guid, image=d.get("Image",""), parent_image=d.get("ParentImage",""),
            cmdline=d.get("CommandLine",""), description="", user=d.get("User",""),
            score=ep["total_score"], timestamp=ts,
        )
        if not inst:
            return

        self._run("MERGE (reg:Registry {id: $id})", {"id": reg_id})
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="MODIFIED_REGISTRY",
            dst_id=reg_id, dst_label="Registry",
            ep=ep, timestamp=ts,
            extra_create={"event_type": event_type},
        )
        self._update_process_score(guid, ep["total_score"])

    def handle_event_12(self, e, d=None): self._handle_registry(e, "add",    d)
    def handle_event_13(self, e, d=None): self._handle_registry(e, "set",    d)
    def handle_event_14(self, e, d=None): self._handle_registry(e, "rename", d)

    def handle_event_15(self, event: dict, detection: Optional[dict] = None):
        """CreateStreamHash (ADS)."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid    = d.get("ProcessGuid") or ""
        file_id = (d.get("TargetFilename") or "").lower()
        if not guid or not file_id:
            return

        inst = self._get_or_create_instance(
            guid=guid, image=d.get("Image",""), parent_image=d.get("ParentImage",""),
            cmdline=d.get("CommandLine",""), description="", user=d.get("User",""),
            score=max(ep["total_score"], 0.5),
            timestamp=ts,
        )
        if not inst:
            return

        self._run("MERGE (f:File {id: $id})", {"id": file_id})
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="WROTE_ADS",
            dst_id=file_id, dst_label="File",
            ep=ep, timestamp=ts,
            extra_create={"stream_name": d.get("StreamName") or ""},
        )
        self._update_process_score(guid, ep["total_score"])

    def handle_event_22(self, event: dict, detection: Optional[dict] = None):
        """DNSQuery."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid  = d.get("ProcessGuid") or ""
        query = (d.get("QueryName") or "").lower()
        if not guid or not query:
            return

        inst = self._get_or_create_instance(
            guid=guid, image=d.get("Image",""), parent_image=d.get("ParentImage",""),
            cmdline=d.get("CommandLine",""), description="", user=d.get("User",""),
            score=ep["total_score"], timestamp=ts,
        )
        if not inst:
            return

        self._run("MERGE (dns:DNS {id: $q})", {"q": query})
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="QUERIED_DNS",
            dst_id=query, dst_label="DNS",
            ep=ep, timestamp=ts,
        )
        self._update_process_score(guid, ep["total_score"])

    def handle_event_23(self, event: dict, detection: Optional[dict] = None):
        """FileDelete."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid    = d.get("ProcessGuid") or ""
        file_id = (d.get("TargetFilename") or "").lower()
        if not guid or not file_id:
            return

        inst = self._get_or_create_instance(
            guid=guid, image=d.get("Image",""), parent_image=d.get("ParentImage",""),
            cmdline=d.get("CommandLine",""), description="", user=d.get("User",""),
            score=ep["total_score"], timestamp=ts,
        )
        if not inst:
            return

        self._run("MERGE (f:File {id: $id})", {"id": file_id})
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="DELETED",
            dst_id=file_id, dst_label="File",
            ep=ep, timestamp=ts,
        )
        self._update_process_score(guid, ep["total_score"])

    def handle_event_25(self, event: dict, detection: Optional[dict] = None):
        """ProcessTampering."""
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        attacker_guid = d.get("ProcessGuid") or ""
        victim_guid   = d.get("TargetProcessGuid") or d.get("target_process_guid") or ""
        if not attacker_guid or not victim_guid:
            return

        forced_score = max(ep["total_score"], 0.7)

        for g, img_key in [(attacker_guid, "Image"), (victim_guid, "TargetImage")]:
            self._get_or_create_instance(
                guid=g, image=d.get(img_key,""), parent_image="",
                cmdline="", description="", user="",
                score=forced_score, timestamp=ts,
            )

        self._merge_edge(
            src_id=attacker_guid, src_label="ProcessInstance",
            rel_type="TAMPERED",
            dst_id=victim_guid, dst_label="ProcessInstance",
            ep=ep, timestamp=ts,
            extra_create={"type": d.get("Type") or ""},
        )
        self._update_process_score(attacker_guid, forced_score)
        self._update_process_score(victim_guid,   forced_score)

    # ──────────────────────────────────────────────────────────────────────────
    # PROCESS EXIT
    # ──────────────────────────────────────────────────────────────────────────

    def handle_event_5(self, event: dict, detection: Optional[dict] = None):
        """ProcessTerminate — mark instance as dead."""
        d    = event.get("data", event)
        guid = d.get("ProcessGuid") or d.get("process_guid") or ""
        ts   = d.get("UtcTime") or self._now()
        if guid:
            self._run(
                """
                MATCH (p:ProcessInstance {id: $guid})
                SET p.alive = false, p.end_time = $ts
                """,
                {"guid": guid, "ts": ts},
            )

    # ──────────────────────────────────────────────────────────────────────────
    # LLM CHAIN-GAP TOOL
    # ──────────────────────────────────────────────────────────────────────────

    def check_chain_gaps(self, guid: str) -> dict:
        """
        Tool for the LLM: given a ProcessInstance guid, returns a report of
        any gaps in the parent chain (nodes linked only to a template, not an instance).
        """
        result = {"guid": guid, "gaps": [], "chain": []}

        rows = self._fetch(
            """
            MATCH (p:ProcessInstance {id: $guid})
            OPTIONAL MATCH (p)-[:CHILD_OF]->(parent_inst:ProcessInstance)
            OPTIONAL MATCH (p)-[:CHILD_OF_TEMPLATE]->(parent_tmpl:ProcessTemplate)
            RETURN
                p.id AS id, p.score AS score, p.image AS image,
                parent_inst.id    AS parent_inst_id,
                parent_tmpl.template_hash AS parent_tmpl_hash,
                parent_tmpl.image         AS parent_tmpl_image
            """,
            {"guid": guid},
        )
        if not rows:
            return {"error": f"No ProcessInstance found for guid={guid}"}

        r = rows[0]
        result["chain"].append({
            "id": r["id"], "image": r["image"], "score": r["score"]
        })

        if r["parent_inst_id"]:
            result["chain"].append({"id": r["parent_inst_id"], "type": "instance"})
        elif r["parent_tmpl_hash"]:
            result["gaps"].append({
                "type":         "parent_only_in_template",
                "template_hash": r["parent_tmpl_hash"],
                "parent_image":  r["parent_tmpl_image"],
                "message":       (
                    f"Parent '{r['parent_tmpl_image']}' has no ProcessInstance "
                    f"(never triggered a detection). Chain is incomplete here."
                ),
            })

        return result

    # ──────────────────────────────────────────────────────────────────────────
    # DISPATCHER
    # ──────────────────────────────────────────────────────────────────────────

    _HANDLERS = {
        1:  "handle_event_1",
        2:  "handle_event_2",
        3:  "handle_event_3",
        5:  "handle_event_5",
        6:  "handle_event_6",
        7:  "handle_event_7",
        8:  "handle_event_8",
        10: "handle_event_10",
        11: "handle_event_11",
        12: "handle_event_12",
        13: "handle_event_13",
        14: "handle_event_14",
        15: "handle_event_15",
        22: "handle_event_22",
        23: "handle_event_23",
        25: "handle_event_25",
    }

    def process_event(self, event: dict, detection: Optional[dict] = None):
        try:
            event_id     = int(event.get("event_id", -1))
            handler_name = self._HANDLERS.get(event_id)
            if handler_name:
                getattr(self, handler_name)(event, detection)
            else:
                print(f"[GRAPH] No handler for event_id={event_id}")
        except Exception:
            traceback.print_exc()