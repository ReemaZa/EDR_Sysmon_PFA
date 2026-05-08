"""
graph_builder_batch.py  —  Sysmon → Memgraph  (v4.0  +  batch layer)
=====================================================================

Identical logic to graph_builder.py.
Added on top:
    - process_event_batch(events, detections)   ← new public entry point
    - _BATCH_HANDLERS dispatch table
    - _batch_upsert_templates()                 ← shared UNWIND helper
    - _batch_upsert_instances()                 ← shared UNWIND helper
    - _batch_merge_edges()                      ← shared UNWIND helper
    - _batch_handle_event_1()
    - _batch_handle_single_process_artifact()   ← generic for EV2/3/6/7/11/12-14/15/22/23
    - _batch_handle_dual_process()              ← generic for EV8/10/25
    - _batch_handle_event_5()
    - thin wrappers for every event id

All original single-event methods (handle_event_*, process_event) are
untouched so existing call-sites keep working during migration.
"""

import hashlib
import json
import re
import traceback
from collections import defaultdict
from datetime import datetime
from typing import Optional

from gqlalchemy import Memgraph

MEMGRAPH_HOST = "localhost"
MEMGRAPH_PORT = 7687

EDGE_WEIGHTS: dict[str, int] = {
    "INJECTED_THREAD": 4,
    "ACCESSED_MEMORY": 3,
    "TAMPERED":        3,
    "TIMESTOMPED":     2,
}

ALWAYS_STORE: set[str] = set()

PARENT_INHERITANCE = 0.4
FINDING_IDS_CAP    = 20


# ══════════════════════════════════════════════════════════════════════════════
class GraphBuilderBatch:

    def __init__(self):
        self.db = Memgraph(host=MEMGRAPH_HOST, port=MEMGRAPH_PORT)
        self._init_schema()

    # ─────────────────────────────────────────
    # DB LAYER
    # ─────────────────────────────────────────

    def _run(self, query: str, params: dict = {}) -> bool:
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
        for c in [
            "CREATE CONSTRAINT ON (n:Image) ASSERT n.id IS UNIQUE",
            "CREATE CONSTRAINT ON (n:ProcessTemplate) ASSERT n.template_hash IS UNIQUE",
            "CREATE CONSTRAINT ON (n:ProcessInstance) ASSERT n.id             IS UNIQUE",
            "CREATE CONSTRAINT ON (n:File)            ASSERT n.id             IS UNIQUE",
            "CREATE CONSTRAINT ON (n:Network)         ASSERT n.id             IS UNIQUE",
            "CREATE CONSTRAINT ON (n:Registry)        ASSERT n.id             IS UNIQUE",
            "CREATE CONSTRAINT ON (n:DNS)             ASSERT n.id             IS UNIQUE",
            "CREATE CONSTRAINT ON (n:Driver)          ASSERT n.id             IS UNIQUE",
            "CREATE CONSTRAINT ON (n:User) ASSERT n.id IS UNIQUE",
        ]:
            try:
                self._run(c)
            except Exception:
                pass

    # ─────────────────────────────────────────
    # HASH HELPERS
    # ─────────────────────────────────────────

    @staticmethod
    def _now() -> str:
        return datetime.utcnow().isoformat()

    @staticmethod
    def _h(obj) -> str:
        return hashlib.sha256(
            json.dumps(obj, sort_keys=True, ensure_ascii=True).encode()
        ).hexdigest()

    @classmethod
    def _template_hash(cls, image: str, parent_image: str,
                       cmdline: str, user: str) -> str:
        def norm(cmd: str) -> str:
            cmd = cmd.lower().strip()
            cmd = re.sub(r"[a-z]:\\[^\s]+\\", "", cmd)
            cmd = re.sub(r"\s+", " ", cmd)
            return cmd[:256]
        return cls._h({
            "image":        (image        or "").lower(),
            "parent_image": (parent_image or "").lower(),
            "cmdline":      norm(cmdline  or ""),
        })

    @classmethod
    def _edge_hash(cls, src_id: str, rel_type: str, dst_id: str,
                   techniques: list, tactics: list) -> str:
        sig = cls._h({
            "techniques": sorted(techniques),
            "tactics":    sorted(tactics),
        })
        return cls._h({
            "src":       src_id,
            "rel":       rel_type,
            "dst":       dst_id,
            "alert_sig": sig,
        })

    @staticmethod
    def _edge_params(detection: Optional[dict]) -> dict:
        if not detection:
            return {
                "finding_ids": [],
                "techniques":  [],
                "tactics":     [],
                "total_score": 0,
            }
        return {
            "finding_ids": detection.get("finding_ids", []),
            "techniques":  detection.get("techniques",  []),
            "tactics":     detection.get("tactics",     []),
            "total_score": int(detection.get("total_score", 0)),
        }

    @staticmethod
    def _effective_score(sigma_score: int, rel_type: str) -> int:
        base = EDGE_WEIGHTS.get(rel_type, 0)
        return max(sigma_score, base)

    # ─────────────────────────────────────────
    # TEMPLATE
    # ─────────────────────────────────────────

    def _upsert_template(
        self,
        image:        str,
        parent_image: str,
        cmdline:      str,
        user:         str,
        description:  str = "",
        timestamp:    str = "",
        score:        int = 0,
    ) -> str:
        t_hash = self._template_hash(image, parent_image, cmdline, user)
        ts     = timestamp or self._now()
        cmdline = re.sub(
            r'(?i)(-encodedcommand|-enc)\s+[A-Za-z0-9+/=]{20,}',
            r'\1 [BASE64-ENCODED-PAYLOAD]',
            cmdline
        )
        self._run(
            """
            MERGE (t:ProcessTemplate {template_hash: $t_hash})
            ON CREATE SET
                t.image        = $image,
                t.parent_image = $parent_image,
                t.cmdline      = $cmdline,
                t.user         = $user,
                t.description  = $description,
                t.seen_count   = 1,
                t.total_score  = $score,
                t.first_seen   = $ts,
                t.last_seen    = $ts
            ON MATCH SET
                t.seen_count  = t.seen_count + 1,
                t.last_seen   = $ts,
                t.total_score = t.total_score + $score
            """,
            {
                "t_hash":       t_hash,
                "image":        (image        or "").lower(),
                "parent_image": (parent_image or "").lower(),
                "cmdline":      (cmdline      or "").lower(),
                "user":         (user         or "").lower(),
                "description":  (description  or "").lower(),
                "score":        score,
                "ts":           ts,
            },
        )
        return t_hash

    # ─────────────────────────────────────────
    # INSTANCE QUERIES
    # ─────────────────────────────────────────

    def _instance_exists(self, guid: str) -> bool:
        return bool(self._fetch(
            "MATCH (p:ProcessInstance {id: $guid}) RETURN p.id AS id",
            {"guid": guid},
        ))

    def _get_score(self, guid: str) -> int:
        rows = self._fetch(
            "MATCH (p:ProcessInstance {id: $guid}) RETURN p.score AS score",
            {"guid": guid},
        )
        return int(rows[0]["score"] or 0) if rows else 0

    def _is_ghost(self, guid: str) -> bool:
        rows = self._fetch(
            "MATCH (p:ProcessInstance {id: $guid}) RETURN p.ghost AS ghost",
            {"guid": guid},
        )
        return bool(rows[0]["ghost"]) if rows else False

    # ─────────────────────────────────────────
    # GHOST CREATION
    # ─────────────────────────────────────────

    def _create_ghost(self, guid: str):
        self._run(
            """
            MERGE (p:ProcessInstance {id: $guid})
            ON CREATE SET
                p.ghost = true,
                p.score = 0,
                p.alive = true
            """,
            {"guid": guid},
        )

    # ─────────────────────────────────────────
    # FULL INSTANCE CREATION / GHOST PROMOTION
    # ─────────────────────────────────────────

    def _create_or_promote_instance(
        self,
        guid:         str,
        image:        str,
        parent_image: str,
        cmdline:      str,
        user:         str,
        description:  str,
        score:        int,
        timestamp:    str,
        t_hash:       str,
        pid:          object,
    ) -> str:
        if not guid:
            return ""
        if not t_hash:
            t_hash = self._template_hash(image, parent_image, cmdline, user)
        ts = timestamp or self._now()

        if user:
            self._run(
                "MERGE (u:User {id: $user})",
                {"user": user},
            )
            self._run(
                """
                MATCH (p:ProcessInstance {id: $guid})
                MATCH (u:User {id: $user})
                MERGE (p)-[:RAN_AS]->(u)
                """,
                {"guid": guid, "user": user},
            )
        self._run(
            """
            MERGE (p:ProcessInstance {id: $guid})
            ON CREATE SET
                p.score      = $score,
                p.alive      = true,
                p.pid        = $pid,
                p.start_time = $ts
            ON MATCH SET
                p.score      = p.score + $score
            """,
            {"guid": guid, "score": score, "ts": ts, "pid": pid},
        )
        self._run(
            """
            MATCH (p:ProcessInstance {id: $guid})
            WHERE NOT EXISTS((p)-[:INSTANCE_OF]->())
            MATCH (t:ProcessTemplate {template_hash: $t_hash})
            MERGE (p)-[:INSTANCE_OF]->(t)
            """,
            {"guid": guid, "t_hash": t_hash},
        )
        return guid

    # ─────────────────────────────────────────
    # SCORE PROPAGATION
    # ─────────────────────────────────────────

    def _propagate_to_children(self, parent_guid: str, parent_score: int):
        children = self._fetch(
            """
            MATCH (c:ProcessInstance)-[:CHILD_OF]->(p:ProcessInstance {id: $guid})
            RETURN c.id AS cid
            """,
            {"guid": parent_guid},
        )
        delta = int(parent_score * PARENT_INHERITANCE)
        if delta <= 0:
            return
        for c in children:
            self._run(
                "MATCH (p:ProcessInstance {id: $guid}) SET p.score = p.score + $d",
                {"guid": c["cid"], "d": delta},
            )

    def _add_score(self, guid: str, delta: int):
        if not guid or delta == 0:
            return
        self._run(
            "MATCH (p:ProcessInstance {id: $guid}) SET p.score = p.score + $d",
            {"guid": guid, "d": delta},
        )

    # ─────────────────────────────────────────
    # PARENT CHAIN
    # ─────────────────────────────────────────

    def _ensure_parent_and_link(
        self,
        child_guid:  str,
        parent_guid: str,
        timestamp:   str,
    ):
        if not parent_guid or not child_guid:
            return
        self._run(
            """
            MATCH (child:ProcessInstance  {id: $child_guid})
            MATCH (parent:ProcessInstance {id: $parent_guid})
            MERGE (child)-[:CHILD_OF]->(parent)
            """,
            {"child_guid": child_guid, "parent_guid": parent_guid},
        )

    # ─────────────────────────────────────────
    # EDGE STORAGE GATE
    # ─────────────────────────────────────────

    def _should_store_edge(self, rel_type: str, process_score: int) -> bool:
        return process_score > 0

    # ─────────────────────────────────────────
    # GENERIC EDGE UPSERT
    # ─────────────────────────────────────────

    def _merge_edge(
        self,
        src_id:       str,
        src_label:    str,
        rel_type:     str,
        dst_id:       str,
        dst_label:    str,
        ep:           dict,
        eff_score:    int,
        timestamp:    str,
        extra_create: dict = {},
    ):
        e_hash   = self._edge_hash(
            src_id, rel_type, dst_id, ep["techniques"], ep["tactics"]
        )
        extra_set = "".join(f", r.{k} = ${k}" for k in extra_create)

        self._run(
            f"""
            MATCH (src:{src_label} {{id: $src_id}})
            MATCH (dst:{dst_label} {{id: $dst_id}})
            MERGE (src)-[r:{rel_type} {{edge_hash: $e_hash}}]->(dst)
            ON CREATE SET
                r.first_seen   = $ts,
                r.last_seen    = $ts,
                r.count        = 1,
                r.total_score  = $score,
                r.finding_ids  = $fids,
                r.techniques   = $techs,
                r.tactics      = $tacs
                {extra_set}
            ON MATCH SET
                r.last_seen   = $ts,
                r.count       = r.count + 1,
                r.total_score = r.total_score + $score,
                r.finding_ids = CASE
                    WHEN size(r.finding_ids) < {FINDING_IDS_CAP}
                    THEN r.finding_ids + $fids
                    ELSE r.finding_ids
                END
            """,
            {
                "src_id": src_id,
                "dst_id": dst_id,
                "e_hash": e_hash,
                "ts":     timestamp,
                "score":  eff_score,
                "fids":   ep["finding_ids"][:FINDING_IDS_CAP],
                "techs":  ep["techniques"],
                "tacs":   ep["tactics"],
                **extra_create,
            },
        )

    # ─────────────────────────────────────────────────────────────────────────
    # ORIGINAL SINGLE-EVENT HANDLERS  (unchanged)
    # ─────────────────────────────────────────────────────────────────────────

    def handle_event_1(self, event: dict, detection: Optional[dict] = None):
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        parent_guid  = d.get("ParentProcessGuid") or ""
        child_guid   = d.get("ProcessGuid")       or ""
        parent_image = (d.get("ParentImage")       or "").lower()
        child_image  = (d.get("Image")             or "").lower()
        parent_cmd   = d.get("ParentCommandLine")  or ""
        child_cmd    = d.get("CommandLine")        or ""
        description  = d.get("Description")        or ""
        user         = (d.get("User")              or "").lower()
        parent_user  = (d.get("ParentUser")        or "").lower()

        eff = ep["total_score"]

        p_hash = self._upsert_template(parent_image, "", parent_cmd, parent_user, "", ts, 0)
        t_hash = self._upsert_template(child_image, parent_image, child_cmd, user,
                                       description, ts, eff)
        child_pid  = int(d.get("ProcessId")       or 0) or None
        parent_pid = int(d.get("ParentProcessId") or 0) or None

        if parent_guid:
            self._create_or_promote_instance(
                guid=parent_guid, image=parent_image,
                parent_image="", cmdline=parent_cmd,
                user=parent_user, description="",
                score=0, timestamp=ts, t_hash=p_hash,
                pid=parent_pid,
            )
        parent_score = self._get_score(parent_guid)
        delta = int(parent_score * PARENT_INHERITANCE)
        eff = eff + delta

        if child_guid:
            self._create_or_promote_instance(
                guid=child_guid, image=child_image,
                parent_image=parent_image, cmdline=child_cmd,
                user=user, description=description,
                score=eff, timestamp=ts, t_hash=t_hash,
                pid=child_pid,
            )

        self._ensure_parent_and_link(
            child_guid=child_guid, parent_guid=parent_guid, timestamp=ts
        )
        self._merge_edge(
            src_id=parent_guid, src_label="ProcessInstance",
            rel_type="CREATED",
            dst_id=child_guid,  dst_label="ProcessInstance",
            ep=ep, eff_score=eff - delta, timestamp=ts,
        )

    def handle_event_2(self, event: dict, detection: Optional[dict] = None):
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid    = d.get("ProcessGuid")      or ""
        file_id = (d.get("TargetFilename")  or "").lower()
        image   = (d.get("Image")           or "").lower()
        cmd     = d.get("CommandLine")      or ""
        user    = (d.get("User")            or "").lower()
        if not guid or not file_id:
            return

        eff    = ep["total_score"]
        t_hash = self._upsert_template(image, "", cmd, user, "", ts, eff)
        pid    = int(d.get("ProcessId") or 0) or None

        self._create_or_promote_instance(
            guid=guid, image=image, parent_image="",
            cmdline=cmd, user=user, description="",
            score=eff, timestamp=ts, t_hash=t_hash, pid=pid,
        )
        sha256 = (d.get("Hashes") or "").split("SHA256=")[-1].split(",")[0].lower() \
            if "SHA256=" in (d.get("Hashes") or "") else ""
        self._run("""
            MERGE (f:File {id: $id})
            ON CREATE SET f.sha256 = $sha256
            ON MATCH SET  f.sha256 = $sha256
        """, {"id": file_id, "sha256": sha256})
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="TIMESTOMPED",
            dst_id=file_id, dst_label="File",
            ep=ep, eff_score=eff, timestamp=ts,
        )

    def handle_event_3(self, event: dict, detection: Optional[dict] = None):
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid   = d.get("ProcessGuid") or ""
        dst_ip = (d.get("DestinationIp") or "").lower()
        image  = (d.get("Image")         or "").lower()
        cmd    = d.get("CommandLine")    or ""
        user   = (d.get("User")          or "").lower()
        if not guid or not dst_ip:
            return

        eff    = ep["total_score"]
        t_hash = self._upsert_template(image, "", cmd, user, "", ts, eff)
        pid    = int(d.get("ProcessId") or 0) or None

        self._create_or_promote_instance(
            guid=guid, image=image, parent_image="",
            cmdline=cmd, user=user, description="",
            score=eff, timestamp=ts, t_hash=t_hash, pid=pid,
        )
        self._run("MERGE (n:Network {id: $ip})", {"ip": dst_ip})
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="CONNECTED",
            dst_id=dst_ip, dst_label="Network",
            ep=ep, eff_score=eff, timestamp=ts,
            extra_create={
                "port":     int(d.get("DestinationPort") or 0),
                "protocol": d.get("Protocol") or "",
            },
        )

    def handle_event_5(self, event: dict, detection: Optional[dict] = None):
        d    = event.get("data", event)
        guid = d.get("ProcessGuid") or ""
        ts   = d.get("UtcTime")     or self._now()
        if guid:
            self._run(
                """
                MATCH (p:ProcessInstance {id: $guid})
                SET p.alive = false, p.end_time = $ts
                """,
                {"guid": guid, "ts": ts},
            )

    def handle_event_6(self, event: dict, detection: Optional[dict] = None):
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid       = d.get("ProcessGuid") or ""
        sha256     = (d.get("Hashes") or "").split("SHA256=")[-1].split(",")[0].lower()
        img_loaded = (d.get("ImageLoaded") or "").lower()
        image      = (d.get("Image")        or "").lower()
        user       = (d.get("User")         or "").lower()
        if not guid or not sha256:
            return

        eff    = ep["total_score"]
        t_hash = self._upsert_template(image, "", "", user, "", ts, eff)
        pid    = int(d.get("ProcessId") or 0) or None

        self._create_or_promote_instance(
            guid=guid, image=image, parent_image="",
            cmdline="", user=user, description="",
            score=eff, timestamp=ts, t_hash=t_hash, pid=pid,
        )
        self._run(
            "MERGE (drv:Driver {id: $s}) ON CREATE SET drv.path = $img",
            {"s": sha256, "img": img_loaded},
        )
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="LOADED_DRIVER",
            dst_id=sha256, dst_label="Driver",
            ep=ep, eff_score=eff, timestamp=ts,
        )

    def handle_event_7(self, event: dict, detection: Optional[dict] = None):
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid       = d.get("ProcessGuid") or ""
        sha256     = (d.get("Hashes") or "").split("SHA256=")[-1].split(",")[0].lower()
        img_loaded = (d.get("ImageLoaded") or "").lower()
        image      = (d.get("Image")       or "").lower()
        user       = (d.get("User")        or "").lower()
        if not guid or not sha256:
            return

        eff    = ep["total_score"]
        t_hash = self._upsert_template(image, "", "", user, "", ts, eff)
        pid    = int(d.get("ProcessId") or 0) or None

        self._create_or_promote_instance(
            guid=guid, image=image, parent_image="",
            cmdline="", user=user, description="",
            score=eff, timestamp=ts, t_hash=t_hash, pid=pid,
        )
        self._run(
            "MERGE (img:Image {id: $s}) ON CREATE SET img.path = $i",
            {"s": sha256, "i": img_loaded},
        )
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="LOADED_IMAGE",
            dst_id=sha256, dst_label="Image",
            ep=ep, eff_score=eff, timestamp=ts,
        )

    def handle_event_8(self, event: dict, detection: Optional[dict] = None):
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        src_guid  = d.get("SourceProcessGuid") or ""
        tgt_guid  = d.get("TargetProcessGuid") or d.get("TargetProcessGUID") or ""
        src_image = (d.get("SourceImage") or "").lower()
        tgt_image = (d.get("TargetImage") or "").lower()
        src_user  = (d.get("SourceUser")  or "").lower()
        tgt_user  = (d.get("TargetUser")  or "").lower()
        if not src_guid or not tgt_guid:
            return

        eff        = ep["total_score"]
        src_t_hash = self._upsert_template(src_image, "", "", src_user, "", ts, eff)
        tgt_t_hash = self._upsert_template(tgt_image, "", "", tgt_user, "", ts, eff)
        src_pid    = int(d.get("SourceProcessId") or 0) or None
        tgt_pid    = int(d.get("TargetProcessId") or 0) or None

        self._create_or_promote_instance(
            guid=src_guid, image=src_image, parent_image="",
            cmdline="", user=src_user, description="",
            score=eff, timestamp=ts, t_hash=src_t_hash, pid=src_pid,
        )
        self._create_or_promote_instance(
            guid=tgt_guid, image=tgt_image, parent_image="",
            cmdline="", user=tgt_user, description="",
            score=eff, timestamp=ts, t_hash=tgt_t_hash, pid=tgt_pid,
        )
        if self._instance_exists(src_guid) and self._instance_exists(tgt_guid):
            self._merge_edge(
                src_id=src_guid, src_label="ProcessInstance",
                rel_type="INJECTED_THREAD",
                dst_id=tgt_guid, dst_label="ProcessInstance",
                ep=ep, eff_score=eff, timestamp=ts,
                extra_create={"start_function": d.get("StartFunction") or ""},
            )

    def handle_event_10(self, event: dict, detection: Optional[dict] = None):
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        src_guid  = d.get("SourceProcessGuid") or d.get("SourceProcessGUID") or ""
        tgt_guid  = d.get("TargetProcessGuid") or d.get("TargetProcessGUID") or ""
        src_image = (d.get("SourceImage") or "").lower()
        tgt_image = (d.get("TargetImage") or "").lower()
        src_user  = (d.get("SourceUser")  or "").lower()
        tgt_user  = (d.get("TargetUser")  or "").lower()
        if not src_guid or not tgt_guid:
            return

        eff        = ep["total_score"]
        src_t_hash = self._upsert_template(src_image, "", "", src_user, "", ts, eff)
        tgt_t_hash = self._upsert_template(tgt_image, "", "", tgt_user, "", ts, eff)
        src_pid    = int(d.get("SourceProcessId") or 0) or None
        tgt_pid    = int(d.get("TargetProcessId") or 0) or None

        self._create_or_promote_instance(
            guid=src_guid, image=src_image, parent_image="",
            cmdline="", user=src_user, description="",
            score=eff, timestamp=ts, t_hash=src_t_hash, pid=src_pid,
        )
        self._create_or_promote_instance(
            guid=tgt_guid, image=tgt_image, parent_image="",
            cmdline="", user=tgt_user, description="",
            score=eff, timestamp=ts, t_hash=tgt_t_hash, pid=tgt_pid,
        )
        if self._instance_exists(src_guid) and self._instance_exists(tgt_guid):
            self._merge_edge(
                src_id=src_guid, src_label="ProcessInstance",
                rel_type="ACCESSED_MEMORY",
                dst_id=tgt_guid, dst_label="ProcessInstance",
                ep=ep, eff_score=eff, timestamp=ts,
                extra_create={"access_mask": d.get("GrantedAccess") or ""},
            )

    def handle_event_11(self, event: dict, detection: Optional[dict] = None):
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid    = d.get("ProcessGuid")     or ""
        file_id = (d.get("TargetFilename") or "").lower()
        sha256  = (d.get("Hashes") or "").split("SHA256=")[-1].split(",")[0].lower() \
            if "SHA256=" in (d.get("Hashes") or "") else ""
        image   = (d.get("Image")          or "").lower()
        cmd     = d.get("CommandLine")     or ""
        user    = (d.get("User")           or "").lower()
        if not guid or not file_id:
            return

        eff    = ep["total_score"]
        t_hash = self._upsert_template(image, "", cmd, user, "", ts, eff)
        pid    = int(d.get("ProcessId") or 0) or None

        self._create_or_promote_instance(
            guid=guid, image=image, parent_image="",
            cmdline=cmd, user=user, description="",
            score=eff, timestamp=ts, t_hash=t_hash, pid=pid,
        )
        self._run("""
            MERGE (f:File {id: $id})
            ON CREATE SET f.sha256 = $sha256
            ON MATCH SET  f.sha256 = $sha256
        """, {"id": file_id, "sha256": sha256})
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="CREATED_FILE",
            dst_id=file_id, dst_label="File",
            ep=ep, eff_score=eff, timestamp=ts,
            extra_create={"size": int(d.get("Size") or 0)},
        )

    def _handle_registry(self, event: dict, event_type: str,
                         detection: Optional[dict] = None):
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid   = d.get("ProcessGuid") or ""
        reg_id = (d.get("TargetObject") or "").lower()
        image  = (d.get("Image")        or "").lower()
        cmd    = d.get("CommandLine")   or ""
        user   = (d.get("User")         or "").lower()
        if not guid or not reg_id:
            return

        eff    = ep["total_score"]
        t_hash = self._upsert_template(image, "", cmd, user, "", ts, eff)
        pid    = int(d.get("ProcessId") or 0) or None

        self._create_or_promote_instance(
            guid=guid, image=image, parent_image="",
            cmdline=cmd, user=user, description="",
            score=eff, timestamp=ts, t_hash=t_hash, pid=pid,
        )
        self._run("MERGE (reg:Registry {id: $id})", {"id": reg_id})
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="MODIFIED_REGISTRY",
            dst_id=reg_id, dst_label="Registry",
            ep=ep, eff_score=eff, timestamp=ts,
            extra_create={"event_type": event_type},
        )

    def handle_event_12(self, e, d=None): self._handle_registry(e, "add",    d)
    def handle_event_13(self, e, d=None): self._handle_registry(e, "set",    d)
    def handle_event_14(self, e, d=None): self._handle_registry(e, "rename", d)

    def handle_event_15(self, event: dict, detection: Optional[dict] = None):
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid    = d.get("ProcessGuid")     or ""
        file_id = (d.get("TargetFilename") or "").lower()
        image   = (d.get("Image")          or "").lower()
        cmd     = d.get("CommandLine")     or ""
        user    = (d.get("User")           or "").lower()
        if not guid or not file_id:
            return

        eff    = ep["total_score"]
        t_hash = self._upsert_template(image, "", cmd, user, "", ts, eff)
        pid    = int(d.get("ProcessId") or 0) or None

        self._create_or_promote_instance(
            guid=guid, image=image, parent_image="",
            cmdline=cmd, user=user, description="",
            score=eff, timestamp=ts, t_hash=t_hash, pid=pid,
        )
        sha256 = (d.get("Hashes") or "").split("SHA256=")[-1].split(",")[0].lower() \
            if "SHA256=" in (d.get("Hashes") or "") else ""
        self._run("""
            MERGE (f:File {id: $id})
            ON CREATE SET f.sha256 = $sha256
            ON MATCH SET  f.sha256 = $sha256
        """, {"id": file_id, "sha256": sha256})
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="WROTE_ADS",
            dst_id=file_id, dst_label="File",
            ep=ep, eff_score=eff, timestamp=ts,
            extra_create={"stream_name": d.get("StreamName") or ""},
        )

    def handle_event_22(self, event: dict, detection: Optional[dict] = None):
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid  = d.get("ProcessGuid") or ""
        query = (d.get("QueryName")  or "").lower()
        image = (d.get("Image")      or "").lower()
        cmd   = d.get("CommandLine") or ""
        user  = (d.get("User")       or "").lower()
        if not guid or not query:
            return

        eff    = ep["total_score"]
        t_hash = self._upsert_template(image, "", cmd, user, "", ts, eff)
        pid    = int(d.get("ProcessId") or 0) or None

        self._create_or_promote_instance(
            guid=guid, image=image, parent_image="",
            cmdline=cmd, user=user, description="",
            score=eff, timestamp=ts, t_hash=t_hash, pid=pid,
        )
        self._run("MERGE (dns:DNS {id: $q})", {"q": query})
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="QUERIED_DNS",
            dst_id=query, dst_label="DNS",
            ep=ep, eff_score=eff, timestamp=ts,
        )

    def handle_event_23(self, event: dict, detection: Optional[dict] = None):
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        guid    = d.get("ProcessGuid")     or ""
        file_id = (d.get("TargetFilename") or "").lower()
        image   = (d.get("Image")          or "").lower()
        cmd     = d.get("CommandLine")     or ""
        user    = (d.get("User")           or "").lower()
        if not guid or not file_id:
            return

        eff    = ep["total_score"]
        t_hash = self._upsert_template(image, "", cmd, user, "", ts, eff)
        pid    = int(d.get("ProcessId") or 0) or None

        self._create_or_promote_instance(
            guid=guid, image=image, parent_image="",
            cmdline=cmd, user=user, description="",
            score=eff, timestamp=ts, t_hash=t_hash, pid=pid,
        )
        sha256 = (d.get("Hashes") or "").split("SHA256=")[-1].split(",")[0].lower() \
            if "SHA256=" in (d.get("Hashes") or "") else ""
        self._run("""
            MERGE (f:File {id: $id})
            ON CREATE SET f.sha256 = $sha256
            ON MATCH SET  f.sha256 = $sha256
        """, {"id": file_id, "sha256": sha256})
        self._merge_edge(
            src_id=guid, src_label="ProcessInstance",
            rel_type="DELETED",
            dst_id=file_id, dst_label="File",
            ep=ep, eff_score=eff, timestamp=ts,
        )

    def handle_event_25(self, event: dict, detection: Optional[dict] = None):
        d  = event.get("data", event)
        ep = self._edge_params(detection)
        ts = d.get("UtcTime") or self._now()

        atk_guid  = d.get("ProcessGuid")      or ""
        vic_guid  = d.get("TargetProcessGuid") or d.get("TargetProcessGUID") or ""
        atk_image = (d.get("Image")        or "").lower()
        vic_image = (d.get("TargetImage")  or "").lower()
        atk_user  = (d.get("User")         or "").lower()
        vic_user  = (d.get("TargetUser")   or "").lower()
        if not atk_guid or not vic_guid:
            return

        eff        = ep["total_score"]
        atk_t_hash = self._upsert_template(atk_image, "", "", atk_user, "", ts, eff)
        vic_t_hash = self._upsert_template(vic_image, "", "", vic_user, "", ts, eff)
        src_pid    = int(d.get("SourceProcessId") or 0) or None
        tgt_pid    = int(d.get("TargetProcessId") or 0) or None

        self._create_or_promote_instance(
            guid=atk_guid, image=atk_image, parent_image="",
            cmdline="", user=atk_user, description="",
            score=eff, timestamp=ts, t_hash=atk_t_hash, pid=src_pid,
        )
        self._create_or_promote_instance(
            guid=vic_guid, image=vic_image, parent_image="",
            cmdline="", user=vic_user, description="",
            score=eff, timestamp=ts, t_hash=vic_t_hash, pid=tgt_pid,
        )
        if self._instance_exists(atk_guid) and self._instance_exists(vic_guid):
            self._merge_edge(
                src_id=atk_guid, src_label="ProcessInstance",
                rel_type="TAMPERED",
                dst_id=vic_guid, dst_label="ProcessInstance",
                ep=ep, eff_score=eff, timestamp=ts,
                extra_create={"type": d.get("Type") or ""},
            )

    # ─────────────────────────────────────────
    # LLM TOOL
    # ─────────────────────────────────────────

    def check_chain_gaps(self, guid: str) -> dict:
        rows = self._fetch(
            """
            MATCH (p:ProcessInstance {id: $guid})
            OPTIONAL MATCH (p)-[:CHILD_OF]->(parent:ProcessInstance)
            OPTIONAL MATCH (p)-[:INSTANCE_OF]->(t:ProcessTemplate)
            RETURN
                p.id         AS id,
                p.score      AS score,
                p.ghost      AS ghost,
                t.image      AS image,
                t.user       AS user,
                parent.id    AS parent_id,
                parent.score AS parent_score,
                parent.ghost AS parent_ghost
            """,
            {"guid": guid},
        )
        if not rows:
            return {"error": f"ProcessInstance {guid} not found"}

        r    = rows[0]
        gaps = []

        if r.get("parent_ghost"):
            gaps.append({
                "type":      "ghost_parent",
                "parent_id": r["parent_id"],
                "message": (
                    f"Parent (guid={r['parent_id']}) is a ghost — "
                    f"it has never triggered a detection. "
                    f"Chain is structurally complete but parent "
                    f"has no behavioral data. Check child template's "
                    f"parent_image field to identify the binary."
                ),
            })
        elif not r.get("parent_id"):
            gaps.append({
                "type":    "no_parent",
                "message": "No parent — process predates monitoring or is a root process.",
            })

        return {
            "guid":         r["id"],
            "image":        r.get("image"),
            "user":         r.get("user"),
            "score":        r["score"],
            "ghost":        r["ghost"],
            "parent_id":    r.get("parent_id"),
            "parent_score": r.get("parent_score"),
            "parent_ghost": r.get("parent_ghost"),
            "gaps":         gaps,
        }

    # ─────────────────────────────────────────
    # SINGLE-EVENT DISPATCHER  (unchanged)
    # ─────────────────────────────────────────

    _HANDLERS = {
        1:  "handle_event_1",   2:  "handle_event_2",
        3:  "handle_event_3",   5:  "handle_event_5",
        6:  "handle_event_6",   7:  "handle_event_7",
        8:  "handle_event_8",   10: "handle_event_10",
        11: "handle_event_11",  12: "handle_event_12",
        13: "handle_event_13",  14: "handle_event_14",
        15: "handle_event_15",  22: "handle_event_22",
        23: "handle_event_23",  25: "handle_event_25",
    }

    def process_event(self, event: dict, detection: Optional[dict] = None):
        try:
           
            event_id = int(event.get("event_id", -1))
            handler  = self._HANDLERS.get(event_id)
            if handler:
                getattr(self, handler)(event, detection)
            else:
                print(f"[GRAPH] No handler for event_id={event_id}")
        except Exception:
            traceback.print_exc()

    # =========================================================================
    # BATCH LAYER
    # =========================================================================

    # ─────────────────────────────────────────
    # SHARED UNWIND HELPERS
    # ─────────────────────────────────────────

    def _batch_upsert_templates(self, records: list) -> None:
        """
        records keys: t_hash, image, parent_image, cmdline, user,
                      description, score, ts
        """
        if not records:
            return
        self.db.execute(
            """
            UNWIND $records AS r
            MERGE (t:ProcessTemplate {template_hash: r.t_hash})
            ON CREATE SET
                t.image        = r.image,
                t.parent_image = r.parent_image,
                t.cmdline      = r.cmdline,
                t.user         = r.user,
                t.description  = r.description,
                t.seen_count   = 1,
                t.total_score  = r.score,
                t.first_seen   = r.ts,
                t.last_seen    = r.ts
            ON MATCH SET
                t.seen_count  = t.seen_count + 1,
                t.last_seen   = r.ts,
                t.total_score = t.total_score + r.score
            """,
            {"records": records},
        )

    def _batch_upsert_instances(self, records: list) -> None:
        """
        records keys: guid, score, ts, pid, t_hash, user
        """
        if not records:
            return
        self.db.execute(
            """
            UNWIND $records AS r
            MERGE (p:ProcessInstance {id: r.guid})
            ON CREATE SET
                p.score      = r.score,
                p.alive      = true,
                p.pid        = r.pid,
                p.start_time = r.ts,
                p.ghost      = false
            ON MATCH SET
                p.score = p.score + r.score
            """,
            {"records": records},
        )
        # INSTANCE_OF edges
        self.db.execute(
            """
            UNWIND $records AS r
            MATCH (p:ProcessInstance {id: r.guid})
            WHERE NOT EXISTS((p)-[:INSTANCE_OF]->())
            MATCH (t:ProcessTemplate {template_hash: r.t_hash})
            MERGE (p)-[:INSTANCE_OF]->(t)
            """,
            {"records": records},
        )
        # RAN_AS edges
        user_records = [r for r in records if r.get("user")]
        if user_records:
            self.db.execute(
                """
                UNWIND $records AS r
                MERGE (u:User {id: r.user})
                WITH u, r
                MATCH (p:ProcessInstance {id: r.guid})
                MERGE (p)-[:RAN_AS]->(u)
                """,
                {"records": user_records},
            )

    def _batch_merge_edges(
        self,
        edge_records: list,
        src_label:    str,
        rel_type:     str,
        dst_label:    str,
    ) -> None:
        """
        edge_records keys: src_id, dst_id, e_hash, ts, score, fids,
                           techs, tacs  + any extra fields
        """
        if not edge_records:
            return
        extra_keys = [
            k for k in edge_records[0]
            if k not in {"src_id", "dst_id", "e_hash", "ts", "score",
                         "fids", "techs", "tacs"}
        ]
        extra_create = "".join(f", r.{k} = rec.{k}" for k in extra_keys)

        self.db.execute(
            f"""
            UNWIND $records AS rec
            MATCH (src:{src_label} {{id: rec.src_id}})
            MATCH (dst:{dst_label} {{id: rec.dst_id}})
            MERGE (src)-[r:{rel_type} {{edge_hash: rec.e_hash}}]->(dst)
            ON CREATE SET
                r.first_seen  = rec.ts,
                r.last_seen   = rec.ts,
                r.count       = 1,
                r.total_score = rec.score,
                r.finding_ids = rec.fids,
                r.techniques  = rec.techs,
                r.tactics     = rec.tacs
                {extra_create}
            ON MATCH SET
                r.last_seen   = rec.ts,
                r.count       = r.count + 1,
                r.total_score = r.total_score + rec.score,
                r.finding_ids = CASE
                    WHEN size(r.finding_ids) < {FINDING_IDS_CAP}
                    THEN r.finding_ids + rec.fids
                    ELSE r.finding_ids
                END
            """,
            {"records": edge_records},
        )

    # ─────────────────────────────────────────
    # BATCH HANDLER: EVENT 1  (ProcessCreate)
    # ─────────────────────────────────────────

    def _batch_handle_event_1(self, events: list, detections: list) -> None:
        template_records_parent = []
        template_records_child  = []
        instance_records_parent = []
        instance_records_child  = []
        child_of_records        = []
        edge_records            = []

        for evt, det in zip(events, detections):
            d  = evt.get("data", evt)
            ep = self._edge_params(det)
            ts = d.get("UtcTime") or self._now()

            parent_guid  = d.get("ParentProcessGuid") or ""
            child_guid   = d.get("ProcessGuid")       or ""
            parent_image = (d.get("ParentImage")       or "").lower()
            child_image  = (d.get("Image")             or "").lower()
            parent_cmd   = d.get("ParentCommandLine")  or ""
            child_cmd    = d.get("CommandLine")        or ""
            description  = d.get("Description")        or ""
            user         = (d.get("User")              or "").lower()
            parent_user  = (d.get("ParentUser")        or "").lower()
            eff          = ep["total_score"]
            child_pid    = int(d.get("ProcessId")       or 0) or None
            parent_pid   = int(d.get("ParentProcessId") or 0) or None

            p_hash = self._template_hash(parent_image, "", parent_cmd, parent_user)
            t_hash = self._template_hash(child_image, parent_image, child_cmd, user)

            # Parent score lookup is per-event — score inheritance depends on
            # live graph state and cannot be precomputed across the batch.
            parent_score = self._get_score(parent_guid) if parent_guid else 0
            delta        = int(parent_score * PARENT_INHERITANCE)
            child_eff    = eff + delta

            cmdline_clean = re.sub(
                r'(?i)(-encodedcommand|-enc)\s+[A-Za-z0-9+/=]{20,}',
                r'\1 [BASE64-ENCODED-PAYLOAD]', child_cmd
            )

            if parent_guid:
                template_records_parent.append({
                    "t_hash":       p_hash,
                    "image":        parent_image,
                    "parent_image": "",
                    "cmdline":      (parent_cmd or "").lower(),
                    "user":         parent_user,
                    "description":  "",
                    "score":        0,
                    "ts":           ts,
                })
                instance_records_parent.append({
                    "guid":   parent_guid,
                    "score":  0,
                    "ts":     ts,
                    "pid":    parent_pid,
                    "t_hash": p_hash,
                    "user":   parent_user,
                })

            if child_guid:
                template_records_child.append({
                    "t_hash":       t_hash,
                    "image":        child_image,
                    "parent_image": parent_image,
                    "cmdline":      (cmdline_clean or "").lower(),
                    "user":         user,
                    "description":  (description or "").lower(),
                    "score":        child_eff,
                    "ts":           ts,
                })
                instance_records_child.append({
                    "guid":   child_guid,
                    "score":  child_eff,
                    "ts":     ts,
                    "pid":    child_pid,
                    "t_hash": t_hash,
                    "user":   user,
                })

            if parent_guid and child_guid:
                child_of_records.append({
                    "child_guid":  child_guid,
                    "parent_guid": parent_guid,
                })

            if parent_guid and child_guid:
                e_hash = self._edge_hash(
                    parent_guid, "CREATED", child_guid,
                    ep["techniques"], ep["tactics"],
                )
                edge_records.append({
                    "src_id": parent_guid,
                    "dst_id": child_guid,
                    "e_hash": e_hash,
                    "ts":     ts,
                    "score":  eff,          # raw sigma score on the edge
                    "fids":   ep["finding_ids"][:FINDING_IDS_CAP],
                    "techs":  ep["techniques"],
                    "tacs":   ep["tactics"],
                })

        # Execute in dependency order
        self._batch_upsert_templates(template_records_parent)
        self._batch_upsert_templates(template_records_child)
        self._batch_upsert_instances(instance_records_parent)
        self._batch_upsert_instances(instance_records_child)

        if child_of_records:
            # Ghost parents for any parent that doesn't exist yet, then CHILD_OF
            self.db.execute(
                """
                UNWIND $records AS r
                MERGE (parent:ProcessInstance {id: r.parent_guid})
                ON CREATE SET
                    parent.ghost = true,
                    parent.score = 0,
                    parent.alive = true
                WITH parent, r
                MATCH (child:ProcessInstance {id: r.child_guid})
                MERGE (child)-[:CHILD_OF]->(parent)
                """,
                {"records": child_of_records},
            )

        self._batch_merge_edges(
            edge_records, "ProcessInstance", "CREATED", "ProcessInstance"
        )

    # ─────────────────────────────────────────
    # GENERIC: single process → artifact
    # ─────────────────────────────────────────

    def _batch_handle_single_process_artifact(
        self,
        events:              list,
        detections:          list,
        rel_type:            str,
        artifact_label:      str,
        get_artifact_id,     # callable(d) -> str
        get_extra_edge,      # callable(d) -> dict  or  None
        file_with_sha256:    bool = False,
        get_artifact_extras: object = None,  # callable(d) -> list[(query,params)]
    ) -> None:
        template_records = []
        instance_records = []
        edge_records     = []
        file_rows        = []
        artifact_ids     = []

        for evt, det in zip(events, detections):
            d  = evt.get("data", evt)
            ep = self._edge_params(det)
            ts = d.get("UtcTime") or self._now()

            guid        = d.get("ProcessGuid") or ""
            image       = (d.get("Image")         or "").lower()
            cmd         = d.get("CommandLine")    or ""
            user        = (d.get("User")          or "").lower()
            eff         = ep["total_score"]
            pid         = int(d.get("ProcessId") or 0) or None
            artifact_id = get_artifact_id(d)

            if not guid or not artifact_id:
                continue

            t_hash = self._template_hash(image, "", cmd, user)
            template_records.append({
                "t_hash":       t_hash,
                "image":        image,
                "parent_image": "",
                "cmdline":      cmd.lower(),
                "user":         user,
                "description":  "",
                "score":        eff,
                "ts":           ts,
            })
            instance_records.append({
                "guid":   guid,
                "score":  eff,
                "ts":     ts,
                "pid":    pid,
                "t_hash": t_hash,
                "user":   user,
            })

            if file_with_sha256:
                sha256 = (d.get("Hashes") or "").split("SHA256=")[-1].split(",")[0].lower() \
                    if "SHA256=" in (d.get("Hashes") or "") else ""
                file_rows.append({"id": artifact_id, "sha256": sha256})
            else:
                artifact_ids.append(artifact_id)

            extra = get_extra_edge(d) if get_extra_edge else {}
            e_hash = self._edge_hash(
                guid, rel_type, artifact_id, ep["techniques"], ep["tactics"]
            )
            edge_records.append({
                "src_id": guid,
                "dst_id": artifact_id,
                "e_hash": e_hash,
                "ts":     ts,
                "score":  eff,
                "fids":   ep["finding_ids"][:FINDING_IDS_CAP],
                "techs":  ep["techniques"],
                "tacs":   ep["tactics"],
                **extra,
            })

        self._batch_upsert_templates(template_records)
        self._batch_upsert_instances(instance_records)

        # Artifact nodes
        if file_with_sha256 and file_rows:
            self.db.execute(
                """
                UNWIND $rows AS r
                MERGE (f:File {id: r.id})
                ON CREATE SET f.sha256 = r.sha256
                ON MATCH SET  f.sha256 = r.sha256
                """,
                {"rows": file_rows},
            )
        elif artifact_ids:
            unique_ids = list(set(artifact_ids))
            self.db.execute(
                f"UNWIND $ids AS id MERGE (n:{artifact_label} {{id: id}})",
                {"ids": unique_ids},
            )
            # Extra per-artifact merges (e.g. Driver.path, Image.path)
            if get_artifact_extras:
                for evt, det in zip(events, detections):
                    d = evt.get("data", evt)
                    aid = get_artifact_id(d)
                    if not aid:
                        continue
                    for q, p in get_artifact_extras(d, aid):
                        self._run(q, p)

        self._batch_merge_edges(
            edge_records, "ProcessInstance", rel_type, artifact_label
        )

    # ─────────────────────────────────────────
    # GENERIC: dual process (EV8 / EV10 / EV25)
    # ─────────────────────────────────────────

    def _batch_handle_dual_process(
        self,
        events:          list,
        detections:      list,
        rel_type:        str,
        src_guid_field:  str,
        tgt_guid_field:  str,
        src_image_field: str,
        tgt_image_field: str,
        src_user_field:  str,
        tgt_user_field:  str,
        src_pid_field:   str,
        tgt_pid_field:   str,
        get_extra_edge,  # callable(d) -> dict  or  None
    ) -> None:
        src_template_records = []
        tgt_template_records = []
        src_instance_records = []
        tgt_instance_records = []
        edge_records         = []

        for evt, det in zip(events, detections):
            d  = evt.get("data", evt)
            ep = self._edge_params(det)
            ts = d.get("UtcTime") or self._now()

            src_guid  = d.get(src_guid_field)  or ""
            tgt_guid  = d.get(tgt_guid_field)  or ""
            src_image = (d.get(src_image_field) or "").lower()
            tgt_image = (d.get(tgt_image_field) or "").lower()
            src_user  = (d.get(src_user_field)  or "").lower()
            tgt_user  = (d.get(tgt_user_field)  or "").lower()
            eff       = ep["total_score"]
            src_pid   = int(d.get(src_pid_field) or 0) or None
            tgt_pid   = int(d.get(tgt_pid_field) or 0) or None

            if not src_guid or not tgt_guid:
                continue

            sh = self._template_hash(src_image, "", "", src_user)
            th = self._template_hash(tgt_image, "", "", tgt_user)

            src_template_records.append({
                "t_hash": sh, "image": src_image, "parent_image": "",
                "cmdline": "", "user": src_user, "description": "",
                "score": eff, "ts": ts,
            })
            tgt_template_records.append({
                "t_hash": th, "image": tgt_image, "parent_image": "",
                "cmdline": "", "user": tgt_user, "description": "",
                "score": eff, "ts": ts,
            })
            src_instance_records.append({
                "guid": src_guid, "score": eff, "ts": ts,
                "pid": src_pid, "t_hash": sh, "user": src_user,
            })
            tgt_instance_records.append({
                "guid": tgt_guid, "score": eff, "ts": ts,
                "pid": tgt_pid, "t_hash": th, "user": tgt_user,
            })

            extra = get_extra_edge(d) if get_extra_edge else {}
            e_hash = self._edge_hash(
                src_guid, rel_type, tgt_guid, ep["techniques"], ep["tactics"]
            )
            edge_records.append({
                "src_id": src_guid,
                "dst_id": tgt_guid,
                "e_hash": e_hash,
                "ts":     ts,
                "score":  eff,
                "fids":   ep["finding_ids"][:FINDING_IDS_CAP],
                "techs":  ep["techniques"],
                "tacs":   ep["tactics"],
                **extra,
            })

        self._batch_upsert_templates(src_template_records)
        self._batch_upsert_templates(tgt_template_records)
        self._batch_upsert_instances(src_instance_records)
        self._batch_upsert_instances(tgt_instance_records)
        self._batch_merge_edges(
            edge_records, "ProcessInstance", rel_type, "ProcessInstance"
        )

    # ─────────────────────────────────────────
    # CONCRETE BATCH HANDLERS
    # ─────────────────────────────────────────

    def _batch_handle_event_2(self, events, detections):
        self._batch_handle_single_process_artifact(
            events, detections,
            rel_type       = "TIMESTOMPED",
            artifact_label = "File",
            get_artifact_id    = lambda d: (d.get("TargetFilename") or "").lower(),
            get_extra_edge     = None,
            file_with_sha256   = True,
        )

    def _batch_handle_event_3(self, events, detections):
        self._batch_handle_single_process_artifact(
            events, detections,
            rel_type       = "CONNECTED",
            artifact_label = "Network",
            get_artifact_id = lambda d: (d.get("DestinationIp") or "").lower(),
            get_extra_edge  = lambda d: {
                "port":     int(d.get("DestinationPort") or 0),
                "protocol": d.get("Protocol") or "",
            },
        )

    def _batch_handle_event_6(self, events, detections):
        def _get_id(d):
            return (d.get("Hashes") or "").split("SHA256=")[-1].split(",")[0].lower()
        def _extras(d, sha):
            return [("MERGE (drv:Driver {id: $s}) ON CREATE SET drv.path = $img",
                     {"s": sha, "img": (d.get("ImageLoaded") or "").lower()})]
        self._batch_handle_single_process_artifact(
            events, detections,
            rel_type            = "LOADED_DRIVER",
            artifact_label      = "Driver",
            get_artifact_id     = _get_id,
            get_extra_edge      = None,
            get_artifact_extras = _extras,
        )

    def _batch_handle_event_7(self, events, detections):
        def _get_id(d):
            return (d.get("Hashes") or "").split("SHA256=")[-1].split(",")[0].lower()
        def _extras(d, sha):
            return [("MERGE (img:Image {id: $s}) ON CREATE SET img.path = $i",
                     {"s": sha, "i": (d.get("ImageLoaded") or "").lower()})]
        self._batch_handle_single_process_artifact(
            events, detections,
            rel_type            = "LOADED_IMAGE",
            artifact_label      = "Image",
            get_artifact_id     = _get_id,
            get_extra_edge      = None,
            get_artifact_extras = _extras,
        )

    def _batch_handle_event_8(self, events, detections):
        self._batch_handle_dual_process(
            events, detections,
            rel_type        = "INJECTED_THREAD",
            src_guid_field  = "SourceProcessGuid",
            tgt_guid_field  = "TargetProcessGuid",
            src_image_field = "SourceImage",
            tgt_image_field = "TargetImage",
            src_user_field  = "SourceUser",
            tgt_user_field  = "TargetUser",
            src_pid_field   = "SourceProcessId",
            tgt_pid_field   = "TargetProcessId",
            get_extra_edge  = lambda d: {"start_function": d.get("StartFunction") or ""},
        )

    def _batch_handle_event_10(self, events, detections):
        self._batch_handle_dual_process(
            events, detections,
            rel_type        = "ACCESSED_MEMORY",
            src_guid_field  = "SourceProcessGuid",
            tgt_guid_field  = "TargetProcessGUID",
            src_image_field = "SourceImage",
            tgt_image_field = "TargetImage",
            src_user_field  = "SourceUser",
            tgt_user_field  = "TargetUser",
            src_pid_field   = "SourceProcessId",
            tgt_pid_field   = "TargetProcessId",
            get_extra_edge  = lambda d: {"access_mask": d.get("GrantedAccess") or ""},
        )

    def _batch_handle_event_11(self, events, detections):
        self._batch_handle_single_process_artifact(
            events, detections,
            rel_type         = "CREATED_FILE",
            artifact_label   = "File",
            get_artifact_id  = lambda d: (d.get("TargetFilename") or "").lower(),
            get_extra_edge   = lambda d: {"size": int(d.get("Size") or 0)},
            file_with_sha256 = True,
        )

    def _batch_handle_registry(self, events, detections, event_type: str):
        self._batch_handle_single_process_artifact(
            events, detections,
            rel_type        = "MODIFIED_REGISTRY",
            artifact_label  = "Registry",
            get_artifact_id = lambda d: (d.get("TargetObject") or "").lower(),
            get_extra_edge  = lambda d: {"event_type": event_type},
        )

    def _batch_handle_event_12(self, e, d): self._batch_handle_registry(e, d, "add")
    def _batch_handle_event_13(self, e, d): self._batch_handle_registry(e, d, "set")
    def _batch_handle_event_14(self, e, d): self._batch_handle_registry(e, d, "rename")

    def _batch_handle_event_15(self, events, detections):
        self._batch_handle_single_process_artifact(
            events, detections,
            rel_type         = "WROTE_ADS",
            artifact_label   = "File",
            get_artifact_id  = lambda d: (d.get("TargetFilename") or "").lower(),
            get_extra_edge   = lambda d: {"stream_name": d.get("StreamName") or ""},
            file_with_sha256 = True,
        )

    def _batch_handle_event_22(self, events, detections):
        self._batch_handle_single_process_artifact(
            events, detections,
            rel_type        = "QUERIED_DNS",
            artifact_label  = "DNS",
            get_artifact_id = lambda d: (d.get("QueryName") or "").lower(),
            get_extra_edge  = None,
        )

    def _batch_handle_event_23(self, events, detections):
        self._batch_handle_single_process_artifact(
            events, detections,
            rel_type         = "DELETED",
            artifact_label   = "File",
            get_artifact_id  = lambda d: (d.get("TargetFilename") or "").lower(),
            get_extra_edge   = None,
            file_with_sha256 = True,
        )

    def _batch_handle_event_25(self, events, detections):
        self._batch_handle_dual_process(
            events, detections,
            rel_type        = "TAMPERED",
            src_guid_field  = "ProcessGuid",
            tgt_guid_field  = "TargetProcessGuid",
            src_image_field = "Image",
            tgt_image_field = "TargetImage",
            src_user_field  = "User",
            tgt_user_field  = "TargetUser",
            src_pid_field   = "SourceProcessId",
            tgt_pid_field   = "TargetProcessId",
            get_extra_edge  = lambda d: {"type": d.get("Type") or ""},
        )

    def _batch_handle_event_5(self, events, detections):
        records = []
        for evt, _ in zip(events, detections):
            d    = evt.get("data", evt)
            guid = d.get("ProcessGuid") or ""
            ts   = d.get("UtcTime")     or self._now()
            if guid:
                records.append({"guid": guid, "ts": ts})
        if records:
            self.db.execute(
                """
                UNWIND $records AS r
                MATCH (p:ProcessInstance {id: r.guid})
                SET p.alive = false, p.end_time = r.ts
                """,
                {"records": records},
            )

    # ─────────────────────────────────────────
    # BATCH DISPATCHER
    # ─────────────────────────────────────────

    _BATCH_HANDLERS = {
        1:  "_batch_handle_event_1",
        2:  "_batch_handle_event_2",
        3:  "_batch_handle_event_3",
        5:  "_batch_handle_event_5",
        6:  "_batch_handle_event_6",
        7:  "_batch_handle_event_7",
        8:  "_batch_handle_event_8",
        10: "_batch_handle_event_10",
        11: "_batch_handle_event_11",
        12: "_batch_handle_event_12",
        13: "_batch_handle_event_13",
        14: "_batch_handle_event_14",
        15: "_batch_handle_event_15",
        22: "_batch_handle_event_22",
        23: "_batch_handle_event_23",
        25: "_batch_handle_event_25",
    }

    def process_event_batch(self, events: list, detections: list) -> None:
        """
        Public batch entry point.

        Groups events by event_id, dispatches each group to the
        corresponding batch handler.  Falls back to single-event
        process_event() for any event_id without a batch handler.

        Args:
            events:     list of raw event dicts
            detections: parallel list of detection dicts (None-safe)
        """
        groups:  dict[int, list] = defaultdict(list)
        det_map: dict[int, list] = defaultdict(list)

        for i, evt in enumerate(events):
            eid = int(evt.get("event_id", -1))
            groups[eid].append(evt)
            det_map[eid].append(detections[i] if i < len(detections) else None)

        for eid, evts in groups.items():
            dets    = det_map[eid]
            handler = self._BATCH_HANDLERS.get(eid)
            if handler:
                try:
                    getattr(self, handler)(evts, dets)
                except Exception:
                    traceback.print_exc()
            else:
                # Fallback: single-event path
                print(f"[GRAPH BATCH] No batch handler for event_id={eid}, falling back")
                for evt, det in zip(evts, dets):
                    self.process_event(evt, det)