"""
remediation_context_builder.py
================================
Bridges the analyst agent output and the remediation agent.

Responsibilities:
  1. resolve_guids_from_analyst_actions()
       Every analyst action type (process_termination, file_quarantine,
       ip_block, dns_block, identity_revocation, host_isolation) is traced
       back to one or more process GUIDs using PAT reverse indexes.

  2. deduplicate_by_ancestry()
       If guid B is already a descendant of guid A (both flagged),
       keep only A — B will appear naturally in A's blast radius.

  3. group_by_attack_chain()
       GUIDs that share ancestry are grouped into one chain.
       Unrelated GUIDs become separate chains → separate remediation calls.

  4. build_compact_summary()
       For each chain, pulls PAT context + graph scores and distills into
       a small, bounded dict that fits in the LLM context window.
       Raw PAT action logs are NEVER passed to the LLM directly.

Usage (from threat_analyst.py _tick):
    from remediation_context_builder import RemediationContextBuilder

    rcb     = RemediationContextBuilder(pat=process_artifact_tree, graph_db=graph_builder.db)
    summaries = rcb.build_summaries_from_finding(finding)
    for summary in summaries:
        remediation_agent.run(summary)
"""

from __future__ import annotations

from typing import Optional

from pat_builder import PATBuilder


# ══════════════════════════════════════════════════════════════════════════════
class RemediationContextBuilder:

    def __init__(self, pat: PATBuilder, graph_db=None):
        """
        pat      : live PATBuilder instance (shared with agent.py)
        graph_db : Memgraph connection (graph_builder.db) — used to fetch
                   process scores for infection-point detection.
                   Pass None to skip score annotation (scores will be 0).
        """
        self.pat      = pat
        self.graph_db = graph_db

    # ──────────────────────────────────────────────────────────────────────────
    # PUBLIC: MAIN ENTRY POINT
    # ──────────────────────────────────────────────────────────────────────────

    def build_summaries_from_finding(self, finding) -> list[dict]:
        """
        Given an AnalystFinding object, returns one compact summary dict
        per independent attack chain found in the finding's actions.

        Each summary is safe to pass directly to the remediation agent LLM.
        """
        if not finding or not finding.actions:
            return []

        # Step 1 — resolve every action to process GUIDs
        resolved = self.resolve_guids_from_analyst_actions(
            finding.actions,
            analyst_executed=finding.actions,
        )

        if not resolved["guids"]:
            return []

        # Step 2 — remove GUIDs already covered by an ancestor in the set
        root_guids = self.deduplicate_by_ancestry(resolved["guids"])

        # Step 3 — group by shared ancestry into independent chains
        chains = self.group_by_attack_chain(root_guids)

        # Step 4 — build one compact summary per chain
        summaries = []
        for chain_guids in chains:
            summary = self.build_compact_summary(
                chain_guids          = chain_guids,
                analyst_actions      = finding.actions,
                analyst_verdict      = finding.verdict,
                analyst_anchor       = finding.anchor_guid,
                extra_artifacts      = resolved["extra_artifacts"],
            )
            summaries.append(summary)

        return summaries

    # ──────────────────────────────────────────────────────────────────────────
    # STEP 1 — RESOLVE ANALYST ACTIONS → GUIDS
    # ──────────────────────────────────────────────────────────────────────────

    def resolve_guids_from_analyst_actions(
        self,
        actions: list,
        analyst_executed: list = None,
    ) -> dict:
        """
        Accepts the list of action objects from the analyst finding.
        Returns:
          {
            "guids":           set of process GUIDs,
            "extra_artifacts": {
                "files_to_quarantine": [...],
                "ips_to_block":        [...],
                "domains_to_block":    [...],
                "users_to_revoke":     [...],
                "hosts_to_isolate":    [...],
            }
          }

        For each action type the resolution logic is:
          process_termination  → guid is explicit
          file_quarantine      → reverse file index  → owning guid(s)
          ip_block             → reverse ip index    → owning guid(s)
          dns_block            → reverse dns index   → owning guid(s)
          identity_revocation  → no process guid, stored in extra_artifacts
          host_isolation       → all guids on host via host index
        """
        guids            = set()
        files_quarantine = []
        ips_block        = []
        domains_block    = []
        users_revoke     = []
        hosts_isolate    = []

        for action in (actions or []):
            # Support both object-style and dict-style actions
            atype  = _get(action, "action_type") or _get(action, "action") or ""
            target = _get(action, "target") or {}
            atype  = atype.lower().strip()

            if atype == "process_termination":
                guid = _get(target, "guid") or _get(action, "guid") or ""
                if guid:
                    guids.add(guid)

            elif atype == "file_quarantine":
                path = (_get(target, "file") or _get(target, "path") or "").lower()
                if path:
                    files_quarantine.append(path)
                    owning = self.pat.find_guids_by_file(path)
                    guids.update(owning)

            elif atype == "ip_block":
                ip = (_get(target, "ip") or "").lower()
                if ip:
                    ips_block.append(ip)
                    owning = self.pat.find_guids_by_ip(ip)
                    guids.update(owning)

            elif atype == "dns_block":
                domain = (_get(target, "domain") or _get(target, "dns") or "").lower()
                if domain:
                    domains_block.append(domain)
                    owning = self.pat.find_guids_by_domain(domain)
                    guids.update(owning)

            elif atype == "identity_revocation":
                user = _get(target, "user") or _get(target, "username") or ""
                if user:
                    users_revoke.append(user)
                    # Also try to find processes run by this user in PAT via
                    # host_index scan — best effort, not exhaustive
                    # (identity revocation is an OS-level action, not process-level)

            elif atype == "host_isolation":
                host_id = _get(target, "host_id") or _get(target, "host") or ""
                if host_id:
                    hosts_isolate.append(host_id)
                    all_on_host = self.pat.get_guids_on_host(host_id)
                    guids.update(all_on_host)

        return {
            "guids": guids,
            "extra_artifacts": {
                "files_to_quarantine": list(set(files_quarantine)),
                "ips_to_block":        list(set(ips_block)),
                "domains_to_block":    list(set(domains_block)),
                "users_to_revoke":     list(set(users_revoke)),
                "hosts_to_isolate":    list(set(hosts_isolate)),
            },
        }

    # ──────────────────────────────────────────────────────────────────────────
    # STEP 2 — DEDUPLICATE BY ANCESTRY
    # ──────────────────────────────────────────────────────────────────────────

    def deduplicate_by_ancestry(self, guids: set) -> set:
        """
        Remove any guid whose ancestor is already in the set.
        E.g. if {aaa, bbb} and bbb is a descendant of aaa → return {aaa}.
        bbb will appear in aaa's blast radius automatically.
        """
        if len(guids) <= 1:
            return guids

        # Build ancestry chains for each guid
        chains = {g: set(self.pat.get_parent_chain(g)) for g in guids}

        # Keep guid only if none of the OTHER guids is its ancestor
        result = set()
        for g in guids:
            ancestors = chains[g]
            dominated = any(
                other != g and other in ancestors
                for other in guids
            )
            if not dominated:
                result.add(g)

        return result

    # ──────────────────────────────────────────────────────────────────────────
    # STEP 3 — GROUP BY ATTACK CHAIN
    # ──────────────────────────────────────────────────────────────────────────

    def group_by_attack_chain(self, guids: set) -> list[list[str]]:
        """
        Group GUIDs that share at least one common ancestor into the same chain.
        Each group will become one remediation agent call.

        Returns list of groups, each group is a list of root GUIDs for that chain.
        """
        if not guids:
            return []

        # Build ancestry set per guid
        ancestry = {g: set(self.pat.get_parent_chain(g)) for g in guids}

        # Union-Find grouping: two GUIDs are in the same chain if their
        # ancestry sets overlap at any point
        groups: list[set] = []
        for g in guids:
            merged = False
            for group in groups:
                # Check if g shares any ancestor with any guid in this group
                group_ancestors = set()
                for existing in group:
                    group_ancestors.update(ancestry[existing])
                if ancestry[g] & group_ancestors or g in group_ancestors:
                    group.add(g)
                    merged = True
                    break
            if not merged:
                groups.append({g})

        return [list(g) for g in groups]

    # ──────────────────────────────────────────────────────────────────────────
    # STEP 4 — BUILD COMPACT SUMMARY
    # ──────────────────────────────────────────────────────────────────────────

    def build_compact_summary(
        self,
        chain_guids:      list[str],
        analyst_actions:  list,
        analyst_verdict:  str,
        analyst_anchor:   str,
        extra_artifacts:  dict,
    ) -> dict:
        """
        Builds the compact summary passed to the remediation agent LLM.

        Structure:
        {
          "analyst_verdict":         str,
          "analyst_anchor":          str,
          "analyst_actions_executed": [...],   ← what analyst already decided
          "infection_point":         {...},     ← first scored node in ancestry
          "origin_chain": [...],               ← clean ancestors (don't kill)
          "blast_radius": [...],               ← processes to kill/inspect
          "injection_victims": [...],          ← cross-process targets
          "artifacts": {
            "files_created":  [...],
            "files_deleted":  [...],
            "registry_keys":  [...],
            "dns_queries":    [...],
            "network_conns":  [...],
            "files_to_quarantine": [...],      ← from analyst directly
            "ips_to_block":        [...],
            "domains_to_block":    [...],
            "users_to_revoke":     [...],
          },
          "hosts_involved":  [...],
          "chain_truncated": bool,
          "note": str,                         ← human-readable warning if truncated
        }
        """
        # Merge PAT contexts for all root guids in this chain
        # (usually just one, but could be two unrelated roots grouped together)
        all_ancestry     = []
        all_blast        = []
        all_victims      = []
        chain_truncated  = False
        seen_guids       = set()

        for root_guid in chain_guids:
            ctx = self.pat.build_remediation_context(root_guid)
            chain_truncated = chain_truncated or ctx["chain_truncated"]

            for node in ctx["ancestry_chain"]:
                if node["guid"] not in seen_guids:
                    seen_guids.add(node["guid"])
                    all_ancestry.append(node)

            for node in ctx["blast_radius"]:
                if node["guid"] not in seen_guids:
                    seen_guids.add(node["guid"])
                    all_blast.append(node)

            for v in ctx["injection_victims"]:
                if v["guid"] not in seen_guids:
                    seen_guids.add(v["guid"])
                    all_victims.append(v)

        # ── Fetch graph scores and find infection point ───────────────────────
        scores = self._fetch_graph_scores([n["guid"] for n in all_ancestry + all_blast])

        infection_point = None
        for node in all_ancestry:
            score = scores.get(node["guid"], 0)
            if score > 0:
                infection_point = {
                    "guid":         node["guid"],
                    "image":        node["image"],
                    "parent_image": node["parent_image"],
                    "score":        score,
                }
                break  # first scored ancestor = infection point

        # ── Separate origin (clean) from blast (malicious) ───────────────────
        infection_guid = infection_point["guid"] if infection_point else None
        origin_chain   = []
        in_blast       = False

        for node in all_ancestry:
            if node["guid"] == infection_guid:
                in_blast = True
            if not in_blast:
                origin_chain.append({
                    "guid":  node["guid"],
                    "image": node["image"],
                    "note":  "legitimate parent — do not kill",
                })

        # ── Collect artifacts from blast radius ───────────────────────────────
        files_created  = []
        files_deleted  = []
        registry_keys  = []
        dns_queries    = []
        network_conns  = []
        hosts_involved = set()

        for node in all_blast:
            if node.get("host_id"):
                hosts_involved.add(node["host_id"])
            for action in node.get("actions", []):
                atype = action.get("type", "")
                if atype == "file_created":
                    _append_unique(files_created, action.get("path", ""))
                elif atype == "file_deleted":
                    _append_unique(files_deleted, action.get("path", ""))
                elif atype == "registry_write":
                    _append_unique(registry_keys, action.get("key", ""))
                elif atype == "dns_query":
                    _append_unique(dns_queries, action.get("query", ""))
                elif atype == "network_connection":
                    entry = action.get("dst_ip", "")
                    port  = action.get("dst_port", "")
                    if entry:
                        _append_unique(network_conns, f"{entry}:{port}" if port else entry)

        # ── Format blast radius for LLM (compact — no raw action dumps) ───────
        blast_summary = []
        for node in all_blast:
            blast_summary.append({
                "guid":       node["guid"],
                "image":      node["image"],
                "cmdline":    node["cmdline"],
                "user":       node["user"],
                "alive":      node["alive"],
                "score":      scores.get(node["guid"], 0),
                "confirmed":  node["guid"] in {
                    _get(a, "target", {}).get("guid", "")
                    for a in analyst_actions
                    if (_get(a, "action_type") or _get(a, "action", "")).lower()
                       == "process_termination"
                },
            })

        # ── Format analyst actions for the summary ────────────────────────────
        executed = []
        for a in (analyst_actions or []):
            atype = _get(a, "action_type") or _get(a, "action") or ""
            tgt   = _get(a, "target") or {}
            executed.append({
                "action": atype,
                "target": tgt,
                "reason": _get(a, "reason") or "",
            })

        return {
            "analyst_verdict":          analyst_verdict,
            "analyst_anchor":           analyst_anchor,
            "analyst_actions_executed": executed,
            "infection_point":          infection_point,
            "origin_chain":             origin_chain,
            "blast_radius":             blast_summary,
            "injection_victims":        all_victims,
            "artifacts": {
                "files_created":       files_created,
                "files_deleted":       files_deleted,
                "registry_keys":       registry_keys,
                "dns_queries":         dns_queries,
                "network_conns":       network_conns,
                # From analyst directly (already executed or pending)
                "files_to_quarantine": extra_artifacts.get("files_to_quarantine", []),
                "ips_to_block":        extra_artifacts.get("ips_to_block",        []),
                "domains_to_block":    extra_artifacts.get("domains_to_block",    []),
                "users_to_revoke":     extra_artifacts.get("users_to_revoke",     []),
            },
            "hosts_involved":  list(hosts_involved),
            "chain_truncated": chain_truncated,
            "note": (
                "WARNING: ancestry chain was truncated — some parent processes "
                "are not in PAT (predated monitoring or TTL expired). "
                "Origin may be incomplete."
            ) if chain_truncated else "",
        }

    # ──────────────────────────────────────────────────────────────────────────
    # INTERNAL: GRAPH SCORE FETCH
    # ──────────────────────────────────────────────────────────────────────────

    def _fetch_graph_scores(self, guids: list[str]) -> dict[str, int]:
        """
        Fetch ProcessInstance scores from Memgraph for a list of GUIDs.
        Returns {guid: score}. Missing GUIDs get score=0.
        """
        if not guids or not self.graph_db:
            return {g: 0 for g in guids}

        result = {}
        try:
            rows = list(self.graph_db.execute_and_fetch(
                """
                UNWIND $guids AS g
                OPTIONAL MATCH (p:ProcessInstance {id: g})
                RETURN g AS guid, coalesce(p.score, 0) AS score
                """,
                {"guids": guids},
            ))
            for row in rows:
                result[row["guid"]] = int(row["score"] or 0)
        except Exception as e:
            print(f"[RCB][WARN] Graph score fetch failed: {e} — defaulting to 0")
            result = {g: 0 for g in guids}

        return result


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get(obj, *keys, default=None):
    """Safe get from dict or object for both attribute and key access."""
    for key in keys:
        if obj is None:
            return default
        if isinstance(obj, dict):
            obj = obj.get(key)
        else:
            obj = getattr(obj, key, None)
    return obj if obj is not None else default


def _append_unique(lst: list, value: str):
    if value and value not in lst:
        lst.append(value)