"""
pat_builder.py  —  Process Artifact Tree (PAT)
================================================

DESIGN SUMMARY
──────────────
The PAT is a complete, append-only, per-process forensic ledger stored in Redis.
It runs in PARALLEL with the graph builder and is updated on EVERY event,
regardless of whether the event matches a Sigma rule or not.

Unlike the threat graph (which is sparse, scored, and pruned), the PAT:
  - Stores ALL events for ALL processes unconditionally
  - Is NEVER pruned by score
  - Has its own TTL (default 7 days) independent of Memgraph pruning
  - Is the ground truth used by the Remediation Agent

Redis Key Layout
────────────────
  pat:identity:{guid}          → Hash   — static process metadata
  pat:actions:{guid}           → Stream — ordered append-only action log
  pat:host_index:{host_id}     → Set    — all GUIDs seen on a host
  pat:children:{guid}          → Set    — direct child GUIDs (for downward walk)
  pat:file_index:{path}        → Set    — GUIDs that touched this file path
  pat:ip_index:{ip}            → Set    — GUIDs that connected to this IP
  pat:dns_index:{domain}       → Set    — GUIDs that queried this domain

Ancestry Walk (O(depth))
────────────────────────
  HGET pat:identity:{guid} parent_guid
  → repeat until parent_guid is empty or missing

Remediation Bundle (built by build_remediation_context)
────────────────────────────────────────────────────────
  Given a flagged GUID, walk ancestry to root, collect all actions per node.
  Returns an ordered list:
    [
      { guid, image, cmdline, user, parent_guid, parent_image, pid, host_id,
        start_time, end_time, alive,
        actions: [ {type, ts, ...fields} ]
      },
      ...  (root first → flagged node last)
    ]
"""

import json
from datetime import datetime, timezone
from typing import Optional

import redis

# ── Redis config (matches your existing sigma engine config) ──────────────────
REDIS_HOST = "localhost"
REDIS_PORT  = 6379
REDIS_DB    = 0

# TTL for all PAT keys: 7 days (independent of Memgraph pruning)
PAT_TTL_SECONDS = 7 * 24 * 3600

# Max actions per process kept in the stream (prevent unbounded growth)
PAT_ACTIONS_MAXLEN = 2000

# Key prefixes
_PFX_IDENTITY  = "pat:identity:"
_PFX_ACTIONS   = "pat:actions:"
_PFX_HOST_IDX  = "pat:host_index:"
_PFX_FILE_IDX  = "pat:file_index:"    # file_path  → Set[guid]
_PFX_IP_IDX    = "pat:ip_index:"      # ip         → Set[guid]
_PFX_DNS_IDX   = "pat:dns_index:"     # domain     → Set[guid]
_PFX_CHILDREN  = "pat:children:"      # guid       → Set[child_guid]


# ══════════════════════════════════════════════════════════════════════════════
class PATBuilder:
    """
    Process Artifact Tree builder.
    One instance lives for the lifetime of the agent process (same pattern as GraphBuilder).
    """

    def __init__(
        self,
        host: str = REDIS_HOST,
        port: int = REDIS_PORT,
        db:   int = REDIS_DB,
    ):
        self.r = redis.Redis(host=host, port=port, db=db, decode_responses=True)
        # Verify connection at startup — fail loud, fail early
        self.r.ping()
        print("[PAT] Connected to Redis — Process Artifact Tree ready.")

    # ──────────────────────────────────────────────────────────────────────────
    # INTERNAL HELPERS
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _identity_key(self, guid: str) -> str:
        return f"{_PFX_IDENTITY}{guid}"

    def _actions_key(self, guid: str) -> str:
        return f"{_PFX_ACTIONS}{guid}"

    def _host_index_key(self, host_id: str) -> str:
        return f"{_PFX_HOST_IDX}{host_id}"

    def _children_key(self, guid: str) -> str:
        return f"{_PFX_CHILDREN}{guid}"

    def _file_index_key(self, path: str) -> str:
        return f"{_PFX_FILE_IDX}{path[:200]}"   # cap key length

    def _ip_index_key(self, ip: str) -> str:
        return f"{_PFX_IP_IDX}{ip}"

    def _dns_index_key(self, domain: str) -> str:
        return f"{_PFX_DNS_IDX}{domain}"

    def _refresh_ttl(self, guid: str):
        """Slide the TTL window on every write so active processes never expire."""
        self.r.expire(self._identity_key(guid), PAT_TTL_SECONDS)
        self.r.expire(self._actions_key(guid),  PAT_TTL_SECONDS)

    def _set_identity(
        self,
        guid:         str,
        image:        str,
        parent_guid:  str,
        parent_image: str,
        cmdline:      str,
        user:         str,
        pid:          Optional[int],
        host_id:      str,
        start_time:   str,
    ):
        """
        Write process identity into Redis Hash.
        Uses HSETNX (set-if-not-exists) for all static fields so a second event
        for the same GUID does NOT overwrite the original spawn metadata.
        Only start_time is HSETNX; end_time and alive are always mutable.
        """
        key = self._identity_key(guid)
        pipe = self.r.pipeline()

        # Static fields — only written once (first event for this GUID)
        for field, value in {
            "guid":         guid,
            "image":        image,
            "parent_guid":  parent_guid,
            "parent_image": parent_image,
            "cmdline":      cmdline,
            "user":         user,
            "pid":          str(pid) if pid else "",
            "host_id":      host_id,
            "start_time":   start_time,
        }.items():
            pipe.hsetnx(key, field, value)

        # Mutable fields — always refreshed
        pipe.hset(key, "alive", "true")
        pipe.hset(key, "end_time", "")

        pipe.expire(key, PAT_TTL_SECONDS)
        pipe.execute()

        # Host index — lets us query "all GUIDs on host X"
        if host_id:
            idx_key = self._host_index_key(host_id)
            self.r.sadd(idx_key, guid)
            self.r.expire(idx_key, PAT_TTL_SECONDS)

        # Children index — register this guid under its parent so we can walk downward
        if parent_guid:
            children_key = self._children_key(parent_guid)
            self.r.sadd(children_key, guid)
            self.r.expire(children_key, PAT_TTL_SECONDS)

    def _append_action(self, guid: str, action_type: str, ts: str, **fields):
        """
        Append one action entry to the process's action stream.
        Uses XADD with MAXLEN to cap stream size.
        Also maintains reverse artifact indexes for O(1) artifact→guid lookup.
        """
        key = self._actions_key(guid)
        entry = {
            "type": action_type,
            "ts":   ts or self._now(),
        }
        for k, v in fields.items():
            if v is not None and v != "":
                entry[k] = str(v)

        self.r.xadd(key, entry, maxlen=PAT_ACTIONS_MAXLEN, approximate=True)
        self.r.expire(key, PAT_TTL_SECONDS)

        # ── Reverse artifact indexes ──────────────────────────────────────────
        # file path → guid
        if action_type in ("file_created", "file_modified", "file_deleted",
                           "file_timestomped", "wrote_ads"):
            path = fields.get("path", "")
            if path:
                k = self._file_index_key(path)
                self.r.sadd(k, guid)
                self.r.expire(k, PAT_TTL_SECONDS)

        # ip → guid
        if action_type == "network_connection":
            ip = fields.get("dst_ip", "")
            if ip:
                k = self._ip_index_key(ip)
                self.r.sadd(k, guid)
                self.r.expire(k, PAT_TTL_SECONDS)

        # domain → guid
        if action_type == "dns_query":
            domain = fields.get("query", "")
            if domain:
                k = self._dns_index_key(domain)
                self.r.sadd(k, guid)
                self.r.expire(k, PAT_TTL_SECONDS)

    # ──────────────────────────────────────────────────────────────────────────
    # PUBLIC: MAIN ENTRY POINT
    # ──────────────────────────────────────────────────────────────────────────

    def process_event(self, event: dict) -> None:
        """
        Called on EVERY event — no sigma gate, no score gate.
        Routes to the appropriate handler based on event_id.
        """
        try:
            event_id = int(event.get("event_id", -1))
            handler  = self._HANDLERS.get(event_id)
            if handler:
                getattr(self, handler)(event)
            # Events with no handler are silently skipped (e.g. Sysmon event types
            # we don't care about for forensics). No error logged — by design.
        except Exception as e:
            print(f"[PAT][ERROR] event_id={event.get('event_id')} → {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # EVENT HANDLERS
    # ──────────────────────────────────────────────────────────────────────────

    def _handle_event_1(self, event: dict):
        """
        Event 1 — ProcessCreate.
        This is the ONLY event that writes parent_guid and parent_image.
        Both parent and child identities are written here.
        """
        d            = event.get("data", event)
        ts           = d.get("UtcTime")             or self._now()
        host_id      = d.get("Computer")            or event.get("host_id", "")

        child_guid   = d.get("ProcessGuid")         or ""
        child_image  = (d.get("Image")              or "").lower()
        child_cmd    = d.get("CommandLine")         or ""
        child_user   = (d.get("User")               or "").lower()
        child_pid    = int(d.get("ProcessId")       or 0) or None

        parent_guid  = d.get("ParentProcessGuid")   or ""
        parent_image = (d.get("ParentImage")         or "").lower()
        parent_cmd   = d.get("ParentCommandLine")   or ""
        parent_user  = (d.get("ParentUser")         or "").lower()
        parent_pid   = int(d.get("ParentProcessId") or 0) or None

        # Write parent identity (HSETNX — won't overwrite if already known)
        if parent_guid:
            self._set_identity(
                guid=parent_guid, image=parent_image,
                parent_guid="",   parent_image="",
                cmdline=parent_cmd, user=parent_user,
                pid=parent_pid,   host_id=host_id,
                start_time=ts,
            )
            # Record the spawn action on the parent's action log
            self._append_action(
                parent_guid, "child_spawned", ts,
                child_guid=child_guid,
                child_image=child_image,
                child_cmdline=child_cmd,
            )

        # Write child identity — parent_guid stored here enables ancestry walk
        if child_guid:
            self._set_identity(
                guid=child_guid,    image=child_image,
                parent_guid=parent_guid, parent_image=parent_image,
                cmdline=child_cmd,  user=child_user,
                pid=child_pid,      host_id=host_id,
                start_time=ts,
            )

    def _handle_event_2(self, event: dict):
        """Event 2 — FileCreateTime (Timestomp)."""
        d    = event.get("data", event)
        ts   = d.get("UtcTime") or self._now()
        guid = d.get("ProcessGuid") or ""
        if not guid:
            return
        self._ensure_identity(event)
        self._append_action(
            guid, "file_timestomped", ts,
            path=   (d.get("TargetFilename") or "").lower(),
            sha256= self._extract_sha256(d.get("Hashes", "")),
        )
        self._refresh_ttl(guid)

    def _handle_event_3(self, event: dict):
        """Event 3 — NetworkConnect."""
        d    = event.get("data", event)
        ts   = d.get("UtcTime") or self._now()
        guid = d.get("ProcessGuid") or ""
        if not guid:
            return
        self._ensure_identity(event)
        self._append_action(
            guid, "network_connection", ts,
            dst_ip=   (d.get("DestinationIp")       or "").lower(),
            dst_port= d.get("DestinationPort")      or "",
            src_ip=   (d.get("SourceIp")            or "").lower(),
            src_port= d.get("SourcePort")           or "",
            protocol= (d.get("Protocol")            or "").lower(),
            dst_host= (d.get("DestinationHostname") or "").lower(),
            initiated=d.get("Initiated")            or "",
        )
        self._refresh_ttl(guid)

    def _handle_event_5(self, event: dict):
        """Event 5 — ProcessTerminate. Mark process dead in identity hash."""
        d    = event.get("data", event)
        ts   = d.get("UtcTime") or self._now()
        guid = d.get("ProcessGuid") or ""
        if not guid:
            return
        key = self._identity_key(guid)
        if self.r.exists(key):
            self.r.hset(key, mapping={"alive": "false", "end_time": ts})
            self._refresh_ttl(guid)

    def _handle_event_6(self, event: dict):
        """Event 6 — DriverLoad."""
        d    = event.get("data", event)
        ts   = d.get("UtcTime") or self._now()
        guid = d.get("ProcessGuid") or ""
        if not guid:
            return
        self._ensure_identity(event)
        self._append_action(
            guid, "driver_loaded", ts,
            sha256=      self._extract_sha256(d.get("Hashes", "")),
            image_loaded=(d.get("ImageLoaded") or "").lower(),
            signed=      d.get("Signed")       or "",
            signature=   d.get("Signature")    or "",
        )
        self._refresh_ttl(guid)

    def _handle_event_7(self, event: dict):
        """Event 7 — ImageLoad (DLL)."""
        d    = event.get("data", event)
        ts   = d.get("UtcTime") or self._now()
        guid = d.get("ProcessGuid") or ""
        if not guid:
            return
        self._ensure_identity(event)
        self._append_action(
            guid, "image_loaded", ts,
            image_loaded=(d.get("ImageLoaded") or "").lower(),
            sha256=      self._extract_sha256(d.get("Hashes", "")),
            signed=      d.get("Signed")       or "",
            signature=   d.get("Signature")    or "",
        )
        self._refresh_ttl(guid)

    def _handle_event_8(self, event: dict):
        """Event 8 — CreateRemoteThread (injection source and target)."""
        d      = event.get("data", event)
        ts     = d.get("UtcTime") or self._now()
        src    = d.get("SourceProcessGuid") or ""
        tgt    = d.get("TargetProcessGuid") or d.get("TargetProcessGUID") or ""

        if src:
            self._ensure_identity(event, guid_field="SourceProcessGuid",
                                  image_field="SourceImage", user_field="SourceUser",
                                  pid_field="SourceProcessId")
            self._append_action(
                src, "injected_thread_into", ts,
                target_guid=  tgt,
                target_image= (d.get("TargetImage")    or "").lower(),
                start_address=d.get("StartAddress")    or "",
                start_module= (d.get("StartModule")    or "").lower(),
                start_function=d.get("StartFunction")  or "",
            )
            self._refresh_ttl(src)

        if tgt:
            self._ensure_identity(event, guid_field="TargetProcessGuid",
                                  image_field="TargetImage", user_field="TargetUser",
                                  pid_field="TargetProcessId")
            self._append_action(
                tgt, "received_injected_thread", ts,
                source_guid=   src,
                source_image=  (d.get("SourceImage")   or "").lower(),
                start_address= d.get("StartAddress")   or "",
                start_function=d.get("StartFunction")  or "",
            )
            self._refresh_ttl(tgt)

    def _handle_event_10(self, event: dict):
        """Event 10 — ProcessAccess (memory read/write)."""
        d   = event.get("data", event)
        ts  = d.get("UtcTime") or self._now()
        src = d.get("SourceProcessGuid") or d.get("SourceProcessGUID") or ""
        tgt = d.get("TargetProcessGuid") or d.get("TargetProcessGUID") or ""

        if src:
            self._ensure_identity(event, guid_field="SourceProcessGuid",
                                  image_field="SourceImage", user_field="SourceUser",
                                  pid_field="SourceProcessId")
            self._append_action(
                src, "accessed_process_memory", ts,
                target_guid=  tgt,
                target_image= (d.get("TargetImage")   or "").lower(),
                access_mask=  d.get("GrantedAccess")  or "",
            )
            self._refresh_ttl(src)

        if tgt:
            self._ensure_identity(event, guid_field="TargetProcessGuid",
                                  image_field="TargetImage", user_field="TargetUser",
                                  pid_field="TargetProcessId")
            self._append_action(
                tgt, "memory_was_accessed_by", ts,
                source_guid=  src,
                source_image= (d.get("SourceImage")  or "").lower(),
                access_mask=  d.get("GrantedAccess") or "",
            )
            self._refresh_ttl(tgt)

    def _handle_event_11(self, event: dict):
        """Event 11 — FileCreate."""
        d    = event.get("data", event)
        ts   = d.get("UtcTime") or self._now()
        guid = d.get("ProcessGuid") or ""
        if not guid:
            return
        self._ensure_identity(event)
        self._append_action(
            guid, "file_created", ts,
            path=  (d.get("TargetFilename") or "").lower(),
            sha256=self._extract_sha256(d.get("Hashes", "")),
        )
        self._refresh_ttl(guid)

    def _handle_registry(self, event: dict, event_type: str):
        """Events 12 / 13 / 14 — Registry add / set / rename."""
        d    = event.get("data", event)
        ts   = d.get("UtcTime") or self._now()
        guid = d.get("ProcessGuid") or ""
        if not guid:
            return
        self._ensure_identity(event)
        self._append_action(
            guid, "registry_write", ts,
            reg_type=  event_type,
            key=       (d.get("TargetObject") or "").lower(),
            details=   d.get("Details")       or "",
            new_name=  (d.get("NewName")      or "").lower(),
        )
        self._refresh_ttl(guid)

    def _handle_event_12(self, event): self._handle_registry(event, "add")
    def _handle_event_13(self, event): self._handle_registry(event, "set")
    def _handle_event_14(self, event): self._handle_registry(event, "rename")

    def _handle_event_15(self, event: dict):
        """Event 15 — CreateStreamHash (Alternate Data Stream)."""
        d    = event.get("data", event)
        ts   = d.get("UtcTime") or self._now()
        guid = d.get("ProcessGuid") or ""
        if not guid:
            return
        self._ensure_identity(event)
        self._append_action(
            guid, "wrote_ads", ts,
            path=        (d.get("TargetFilename") or "").lower(),
            stream_name= d.get("StreamName")      or "",
            sha256=      self._extract_sha256(d.get("Hashes", "")),
        )
        self._refresh_ttl(guid)

    def _handle_event_22(self, event: dict):
        """Event 22 — DNSQuery."""
        d    = event.get("data", event)
        ts   = d.get("UtcTime") or self._now()
        guid = d.get("ProcessGuid") or ""
        if not guid:
            return
        self._ensure_identity(event)
        self._append_action(
            guid, "dns_query", ts,
            query=   (d.get("QueryName")    or "").lower(),
            results= d.get("QueryResults")  or "",
            status=  d.get("QueryStatus")   or "",
        )
        self._refresh_ttl(guid)

    def _handle_event_23(self, event: dict):
        """Event 23 — FileDelete."""
        d    = event.get("data", event)
        ts   = d.get("UtcTime") or self._now()
        guid = d.get("ProcessGuid") or ""
        if not guid:
            return
        self._ensure_identity(event)
        self._append_action(
            guid, "file_deleted", ts,
            path=  (d.get("TargetFilename") or "").lower(),
            sha256=self._extract_sha256(d.get("Hashes", "")),
            archived=d.get("IsExecutable") or "",
        )
        self._refresh_ttl(guid)

    def _handle_event_25(self, event: dict):
        """Event 25 — ProcessTampering (hollowing / herpadering)."""
        d   = event.get("data", event)
        ts  = d.get("UtcTime") or self._now()
        atk = d.get("ProcessGuid")      or ""
        vic = d.get("TargetProcessGuid") or d.get("TargetProcessGUID") or ""

        if atk:
            self._ensure_identity(event, guid_field="ProcessGuid",
                                  image_field="Image", user_field="User",
                                  pid_field="ProcessId")
            self._append_action(
                atk, "tampered_process", ts,
                target_guid=  vic,
                target_image= (d.get("TargetImage") or "").lower(),
                tamper_type=  d.get("Type")         or "",
            )
            self._refresh_ttl(atk)

        if vic:
            self._ensure_identity(event, guid_field="TargetProcessGuid",
                                  image_field="TargetImage", user_field="TargetUser",
                                  pid_field="TargetProcessId")
            self._append_action(
                vic, "was_tampered_by", ts,
                source_guid=  atk,
                source_image= (d.get("Image")  or "").lower(),
                tamper_type=  d.get("Type")    or "",
            )
            self._refresh_ttl(vic)

    # ──────────────────────────────────────────────────────────────────────────
    # DISPATCH TABLE
    # ──────────────────────────────────────────────────────────────────────────

    _HANDLERS = {
        1:  "_handle_event_1",
        2:  "_handle_event_2",
        3:  "_handle_event_3",
        5:  "_handle_event_5",
        6:  "_handle_event_6",
        7:  "_handle_event_7",
        8:  "_handle_event_8",
        10: "_handle_event_10",
        11: "_handle_event_11",
        12: "_handle_event_12",
        13: "_handle_event_13",
        14: "_handle_event_14",
        15: "_handle_event_15",
        22: "_handle_event_22",
        23: "_handle_event_23",
        25: "_handle_event_25",
    }

    # ──────────────────────────────────────────────────────────────────────────
    # INTERNAL UTILITIES
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_sha256(hashes_str: str) -> str:
        """Extract SHA256 from sysmon Hashes field e.g. 'SHA256=abc123,MD5=...'"""
        if not hashes_str or "SHA256=" not in hashes_str:
            return ""
        return hashes_str.split("SHA256=")[-1].split(",")[0].lower()

    def _ensure_identity(
        self,
        event: dict,
        guid_field:  str = "ProcessGuid",
        image_field: str = "Image",
        user_field:  str = "User",
        pid_field:   str = "ProcessId",
    ):
        """
        Best-effort identity write for events that are NOT ProcessCreate (Event 1).
        If identity already exists (from Event 1), HSETNX is a no-op — safe to call
        repeatedly. If identity is missing (event arrived before its ProcessCreate),
        we write what we have. parent_guid will be empty — that is acceptable because
        Event 1 will fill it in later via HSETNX-idempotency.
        """
        d       = event.get("data", event)
        guid    = d.get(guid_field)  or ""
        if not guid:
            return
        image   = (d.get(image_field)  or "").lower()
        user    = (d.get(user_field)   or "").lower()
        pid     = int(d.get(pid_field) or 0) or None
        ts      = d.get("UtcTime")     or self._now()
        host_id = d.get("Computer")    or event.get("host_id", "")

        self._set_identity(
            guid=guid, image=image,
            parent_guid="", parent_image="",
            cmdline="",  user=user,
            pid=pid,     host_id=host_id,
            start_time=ts,
        )

    # ──────────────────────────────────────────────────────────────────────────
    # PUBLIC: REMEDIATION CONTEXT BUILDER
    # ──────────────────────────────────────────────────────────────────────────

    def build_remediation_context(
        self,
        flagged_guid: str,
        max_depth: int = 20,
    ) -> dict:
        """
        Given a flagged process GUID, returns the full forensic context:
          - ancestry chain upward to root
          - blast radius downward (all descendants via children index)
          - injection victims (cross-process targets)
          - all artifacts collected from every process in blast radius
          - chain_truncated flag if ancestry walk hit a missing key

        Used by build_compact_summary() — not passed directly to the LLM.
        """
        # ── Step 1: Walk ancestry upward ─────────────────────────────────────
        ancestry_guids = []
        current        = flagged_guid
        seen           = set()
        chain_truncated = False

        for _ in range(max_depth):
            if not current or current in seen:
                break
            seen.add(current)
            ancestry_guids.append(current)
            identity = self.r.hgetall(self._identity_key(current))
            if not identity:
                chain_truncated = True
                break
            parent = identity.get("parent_guid", "")
            if not parent:
                break
            current = parent

        ancestry_guids.reverse()  # root first

        # ── Step 2: Walk blast radius downward from flagged node (BFS) ───────
        blast_guids = []
        queue       = [flagged_guid]
        visited_down = set()

        while queue:
            node = queue.pop(0)
            if node in visited_down:
                continue
            visited_down.add(node)
            blast_guids.append(node)
            children = self.r.smembers(self._children_key(node))
            for child in children:
                if child not in visited_down:
                    queue.append(child)

        # ── Step 3: Collect injection victims from blast radius action logs ───
        injection_victims = []
        seen_victims      = set()
        for guid in blast_guids:
            for action in self.get_actions_by_type(guid, "injected_thread_into"):
                tgt = action.get("target_guid", "")
                if tgt and tgt not in seen_victims and tgt not in visited_down:
                    seen_victims.add(tgt)
                    tgt_identity = self.r.hgetall(self._identity_key(tgt))
                    injection_victims.append({
                        "guid":         tgt,
                        "image":        tgt_identity.get("image", "unknown") if tgt_identity else "unknown",
                        "injected_by":  guid,
                    })

        # ── Step 4: Build full node records ──────────────────────────────────
        def _build_node(guid: str) -> dict:
            identity   = self.r.hgetall(self._identity_key(guid))
            raw_actions = self.r.xrange(self._actions_key(guid))
            actions    = [fields for _, fields in raw_actions]
            if not identity:
                return {
                    "guid": guid, "image": "unknown (not in PAT)",
                    "parent_guid": "", "parent_image": "", "cmdline": "",
                    "user": "", "pid": "", "host_id": "",
                    "start_time": "", "end_time": "", "alive": None,
                    "actions": actions,
                }
            return {
                "guid":         identity.get("guid",         guid),
                "image":        identity.get("image",        ""),
                "parent_guid":  identity.get("parent_guid",  ""),
                "parent_image": identity.get("parent_image", ""),
                "cmdline":      identity.get("cmdline",      ""),
                "user":         identity.get("user",         ""),
                "pid":          identity.get("pid",          ""),
                "host_id":      identity.get("host_id",      ""),
                "start_time":   identity.get("start_time",   ""),
                "end_time":     identity.get("end_time",     ""),
                "alive":        identity.get("alive", "true") == "true",
                "actions":      actions,
            }

        ancestry_chain = [_build_node(g) for g in ancestry_guids
                          if g not in visited_down]  # exclude blast radius nodes
        blast_radius   = [_build_node(g) for g in blast_guids]

        return {
            "flagged_guid":      flagged_guid,
            "chain_truncated":   chain_truncated,
            "ancestry_chain":    ancestry_chain,   # root → infection point (don't kill)
            "blast_radius":      blast_radius,      # flagged + descendants (kill zone)
            "injection_victims": injection_victims, # cross-process targets (scan)
        }

    # ──────────────────────────────────────────────────────────────────────────
    # PUBLIC: ARTIFACT → GUID REVERSE LOOKUPS
    # ──────────────────────────────────────────────────────────────────────────

    def find_guids_by_file(self, path: str) -> list[str]:
        """Return all GUIDs that created/touched this file path."""
        return list(self.r.smembers(self._file_index_key(path.lower())))

    def find_guids_by_ip(self, ip: str) -> list[str]:
        """Return all GUIDs that connected to this IP."""
        return list(self.r.smembers(self._ip_index_key(ip.lower())))

    def find_guids_by_domain(self, domain: str) -> list[str]:
        """Return all GUIDs that queried this domain."""
        return list(self.r.smembers(self._dns_index_key(domain.lower())))

    # ──────────────────────────────────────────────────────────────────────────
    # PUBLIC: LOOKUP HELPERS
    # ──────────────────────────────────────────────────────────────────────────

    def get_identity(self, guid: str) -> Optional[dict]:
        result = self.r.hgetall(self._identity_key(guid))
        return result if result else None

    def get_actions(self, guid: str) -> list[dict]:
        raw = self.r.xrange(self._actions_key(guid))
        return [fields for _, fields in raw]

    def get_actions_by_type(self, guid: str, action_type: str) -> list[dict]:
        return [a for a in self.get_actions(guid) if a.get("type") == action_type]

    def get_guids_on_host(self, host_id: str) -> list[str]:
        return list(self.r.smembers(self._host_index_key(host_id)))

    def get_children(self, guid: str) -> list[str]:
        return list(self.r.smembers(self._children_key(guid)))

    def get_parent_chain(self, guid: str, max_depth: int = 20) -> list[str]:
        """Return ordered list of GUIDs from root to given GUID."""
        chain   = []
        current = guid
        seen    = set()
        for _ in range(max_depth):
            if not current or current in seen:
                break
            seen.add(current)
            chain.append(current)
            identity = self.r.hgetall(self._identity_key(current))
            parent   = identity.get("parent_guid", "") if identity else ""
            if not parent:
                break
            current = parent
        chain.reverse()
        return chain