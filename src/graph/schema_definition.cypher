// ═══════════════════════════════════════════════════════════════════════════════
// SYSMON THREAT DETECTION GRAPH — SCHEMA REFERENCE
// Matches graph_builder.py v2.0 exactly.
//
// DESIGN PRINCIPLES
// ─────────────────
// • ProcessTemplate  → always created, dedup key = sha256(image+parent_image+cmdline)
//                      parent_image baked in: powershell-from-word ≠ powershell-from-explorer
//                      holds NO score, NO parent link — identity only
//
// • ProcessInstance  → created ONLY when total_score > 0 (detection fired)
//                      holds score, alive flag, parent chain, kill target
//
// • All other nodes  → always created on first encounter (MERGE on id)
//
// • Edges            → MERGE key = edge_hash (timestamp excluded)
//                      edge_hash = sha256(src + rel_type + dst + alert_signature)
//                      alert_signature = sha256(sorted techniques + tactics)
//                      same pair + same alert class → count++
//                      same pair + different alert  → new edge
//
// • Score            → lives on ProcessInstance
//                      child inherits parent.score * 0.4
//                      late parent linking propagates score retroactively
// ═══════════════════════════════════════════════════════════════════════════════


// ─────────────────────────────────────────
// CONSTRAINTS
// ─────────────────────────────────────────

CREATE CONSTRAINT ON (n:ProcessTemplate) ASSERT n.template_hash IS UNIQUE;
CREATE CONSTRAINT ON (n:ProcessInstance) ASSERT n.id             IS UNIQUE;
CREATE CONSTRAINT ON (n:File)            ASSERT n.id             IS UNIQUE;
CREATE CONSTRAINT ON (n:Network)         ASSERT n.id             IS UNIQUE;
CREATE CONSTRAINT ON (n:Registry)        ASSERT n.id             IS UNIQUE;
CREATE CONSTRAINT ON (n:DNS)             ASSERT n.id             IS UNIQUE;
CREATE CONSTRAINT ON (n:Driver)          ASSERT n.id             IS UNIQUE;
CREATE CONSTRAINT ON (n:User)            ASSERT n.id             IS UNIQUE;

 
// ─────────────────────────────────────────
// NODE — ProcessTemplate
// Created for every binary seen, regardless of score.
// ─────────────────────────────────────────

MERGE (t:ProcessTemplate {template_hash: $template_hash})
ON CREATE SET
    t.image          = $image,          // lowercase executable path
    t.parent_image   = $parent_image,   // baked into identity (affects hash)
    t.cmdline        = $cmdline,        // normalised: paths stripped, switches kept, max 256 chars
    t.description    = $description,   // PE description when available
    t.seen_count     = 1,
    t.max_seen_score = 0.0              // hint only — updated when any instance gains score
ON MATCH SET
    t.seen_count = t.seen_count + 1;


// ─────────────────────────────────────────
// NODE — ProcessInstance
// Created ONLY when total_score > 0.
// ─────────────────────────────────────────

MERGE (p:ProcessInstance {id: $guid})
ON CREATE SET
    p.image                   = $image,      // lowercase executable path
    p.cmdline                 = $cmdline,    // full command line preserved
    p.user                    = $user,
    p.score                   = $score,      // cumulative suspicion score (mutable)
    p.alive                   = true,
    p.start_time              = $timestamp,
    p.end_time                = null,        // set by Event 5 (ProcessTerminate)
    p.pending_parent_template = $parent_template_hash
                                             // set when parent has no instance yet
                                             // cleared by link_late_children()
ON MATCH SET
    p.score = CASE WHEN $score > p.score THEN $score ELSE p.score END;


// ─────────────────────────────────────────
// NODE — ProcessInstance (process exit, Event 5)
// ─────────────────────────────────────────

MATCH (p:ProcessInstance {id: $guid})
SET p.alive    = false,
    p.end_time = $timestamp;


// ─────────────────────────────────────────
// NODE — Other artifact nodes
// Always created on first encounter.
// ─────────────────────────────────────────

MERGE (f:File     {id: $file_id});          // id = TargetFilename lowercase
MERGE (n:Network  {id: $ip});               // id = DestinationIp  lowercase
MERGE (d:DNS      {id: $query_name});       // id = QueryName      lowercase
MERGE (reg:Registry {id: $target_object}); // id = TargetObject   lowercase
MERGE (u:User     {id: $user});             // id = username string
MERGE (drv:Driver {id: $sha256})            // id = SHA256 hash
ON CREATE SET drv.image = $image_loaded;


// ─────────────────────────────────────────
// STRUCTURAL EDGES (no compression needed)
// ─────────────────────────────────────────

// ProcessInstance → its template (one per instance, never changes)
MATCH (p:ProcessInstance {id: $guid})
MATCH (t:ProcessTemplate {template_hash: $template_hash})
MERGE (p)-[:INSTANCE_OF]->(t);

// ProcessInstance → user account
MATCH (p:ProcessInstance {id: $guid})
MATCH (u:User            {id: $user})
MERGE (p)-[:RAN_AS]->(u);

// ProcessInstance → parent ProcessInstance  (normal case: parent was seen)
MATCH (child:ProcessInstance  {id: $child_guid})
MATCH (parent:ProcessInstance {id: $parent_guid})
MERGE (child)-[:CHILD_OF]->(parent);

// ProcessInstance → parent ProcessTemplate  (fallback: parent never triggered a detection)
// Cleared and replaced with CHILD_OF when parent eventually becomes an instance.
MATCH (child:ProcessInstance {id: $child_guid})
MATCH (pt:ProcessTemplate    {template_hash: $parent_template_hash})
MERGE (child)-[:CHILD_OF_TEMPLATE]->(pt);


// ═══════════════════════════════════════════════════════════════════════════════
// COMPRESSED BEHAVIOUR EDGES
//
// MERGE key  = edge_hash  (timestamp is NEVER part of MERGE)
// ON CREATE  = initialise all fields
// ON MATCH   = update last_seen, count, max_score, append finding_ids (cap 20)
//
// edge_hash  = sha256({src, rel_type, dst, alert_sig})
// alert_sig  = sha256(sorted(techniques + tactics))
//
// Base weights enforced in application layer:
//   CREATED          0.3
//   CONNECTED        0.2
//   INJECTED_THREAD  0.9   (both endpoints always created as instances)
//   ACCESSED_MEMORY  0.8   (both endpoints always created as instances)
//   (others)         detection.total_score
// ═══════════════════════════════════════════════════════════════════════════════


// ─────────────────────────────────────────
// Event 1 — ProcessCreate
// ─────────────────────────────────────────

MATCH (parent:ProcessInstance {id: $parent_guid})
MATCH (child:ProcessInstance  {id: $child_guid})
MERGE (parent)-[r:CREATED {edge_hash: $edge_hash}]->(child)
ON CREATE SET
    r.first_seen  = $timestamp,
    r.last_seen   = $timestamp,
    r.count       = 1,
    r.max_score   = $score,
    r.finding_ids = $finding_ids,   // list, capped at 20, deduped
    r.techniques  = $techniques,
    r.tactics     = $tactics
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.max_score   = CASE WHEN $score > r.max_score THEN $score ELSE r.max_score END,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + [x IN $finding_ids WHERE NOT x IN r.finding_ids]
        ELSE r.finding_ids
    END;


// ─────────────────────────────────────────
// Event 2 — FileCreateTime (Timestomp)
// Minimum score enforced: 0.6
// ─────────────────────────────────────────

MATCH (i:ProcessInstance {id: $guid})
MATCH (f:File            {id: $file_id})
MERGE (i)-[r:TIMESTOMPED {edge_hash: $edge_hash}]->(f)
ON CREATE SET
    r.first_seen  = $timestamp,
    r.last_seen   = $timestamp,
    r.count       = 1,
    r.max_score   = $score,
    r.finding_ids = $finding_ids,
    r.techniques  = $techniques,
    r.tactics     = $tactics
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.max_score   = CASE WHEN $score > r.max_score THEN $score ELSE r.max_score END,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + [x IN $finding_ids WHERE NOT x IN r.finding_ids]
        ELSE r.finding_ids
    END;


// ─────────────────────────────────────────
// Event 3 — NetworkConnect
// Base weight: 0.2
// ─────────────────────────────────────────

MATCH (i:ProcessInstance {id: $guid})
MATCH (n:Network         {id: $dst_ip})
MERGE (i)-[r:CONNECTED {edge_hash: $edge_hash}]->(n)
ON CREATE SET
    r.first_seen  = $timestamp,
    r.last_seen   = $timestamp,
    r.count       = 1,
    r.max_score   = $score,
    r.finding_ids = $finding_ids,
    r.techniques  = $techniques,
    r.tactics     = $tactics,
    r.port        = $port,          // DestinationPort
    r.protocol    = $protocol
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.max_score   = CASE WHEN $score > r.max_score THEN $score ELSE r.max_score END,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + [x IN $finding_ids WHERE NOT x IN r.finding_ids]
        ELSE r.finding_ids
    END;


// ─────────────────────────────────────────
// Event 6 — DriverLoad
// ─────────────────────────────────────────

MATCH (i:ProcessInstance {id: $guid})
MATCH (drv:Driver        {id: $sha256})
MERGE (i)-[r:LOADED_DRIVER {edge_hash: $edge_hash}]->(drv)
ON CREATE SET
    r.first_seen  = $timestamp,
    r.last_seen   = $timestamp,
    r.count       = 1,
    r.max_score   = $score,
    r.finding_ids = $finding_ids,
    r.techniques  = $techniques,
    r.tactics     = $tactics
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.max_score   = CASE WHEN $score > r.max_score THEN $score ELSE r.max_score END,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + [x IN $finding_ids WHERE NOT x IN r.finding_ids]
        ELSE r.finding_ids
    END;


// ─────────────────────────────────────────
// Event 7 — ImageLoad
// ─────────────────────────────────────────

MATCH (i:ProcessInstance {id: $guid})
MATCH (img:Driver        {id: $sha256})
MERGE (i)-[r:LOADED_IMAGE {edge_hash: $edge_hash}]->(img)
ON CREATE SET
    r.first_seen  = $timestamp,
    r.last_seen   = $timestamp,
    r.count       = 1,
    r.max_score   = $score,
    r.finding_ids = $finding_ids,
    r.techniques  = $techniques,
    r.tactics     = $tactics
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.max_score   = CASE WHEN $score > r.max_score THEN $score ELSE r.max_score END,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + [x IN $finding_ids WHERE NOT x IN r.finding_ids]
        ELSE r.finding_ids
    END;


// ─────────────────────────────────────────
// Event 8 — CreateRemoteThread
// Base weight: 0.9  — both endpoints ALWAYS created as instances
// ─────────────────────────────────────────

MATCH (src:ProcessInstance {id: $src_guid})
MATCH (tgt:ProcessInstance {id: $tgt_guid})
MERGE (src)-[r:INJECTED_THREAD {edge_hash: $edge_hash}]->(tgt)
ON CREATE SET
    r.first_seen     = $timestamp,
    r.last_seen      = $timestamp,
    r.count          = 1,
    r.max_score      = $score,
    r.finding_ids    = $finding_ids,
    r.techniques     = $techniques,
    r.tactics        = $tactics,
    r.start_function = $start_function
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.max_score   = CASE WHEN $score > r.max_score THEN $score ELSE r.max_score END,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + [x IN $finding_ids WHERE NOT x IN r.finding_ids]
        ELSE r.finding_ids
    END;


// ─────────────────────────────────────────
// Event 10 — ProcessAccess
// Base weight: 0.8  — both endpoints ALWAYS created as instances
// ─────────────────────────────────────────

MATCH (src:ProcessInstance {id: $src_guid})
MATCH (tgt:ProcessInstance {id: $tgt_guid})
MERGE (src)-[r:ACCESSED_MEMORY {edge_hash: $edge_hash}]->(tgt)
ON CREATE SET
    r.first_seen  = $timestamp,
    r.last_seen   = $timestamp,
    r.count       = 1,
    r.max_score   = $score,
    r.finding_ids = $finding_ids,
    r.techniques  = $techniques,
    r.tactics     = $tactics,
    r.access_mask = $access_mask    // GrantedAccess hex value
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.max_score   = CASE WHEN $score > r.max_score THEN $score ELSE r.max_score END,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + [x IN $finding_ids WHERE NOT x IN r.finding_ids]
        ELSE r.finding_ids
    END;


// ─────────────────────────────────────────
// Event 11 — FileCreate
// ─────────────────────────────────────────

MATCH (i:ProcessInstance {id: $guid})
MATCH (f:File            {id: $file_id})
MERGE (i)-[r:CREATED_FILE {edge_hash: $edge_hash}]->(f)
ON CREATE SET
    r.first_seen  = $timestamp,
    r.last_seen   = $timestamp,
    r.count       = 1,
    r.max_score   = $score,
    r.finding_ids = $finding_ids,
    r.techniques  = $techniques,
    r.tactics     = $tactics,
    r.size        = $size
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.max_score   = CASE WHEN $score > r.max_score THEN $score ELSE r.max_score END,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + [x IN $finding_ids WHERE NOT x IN r.finding_ids]
        ELSE r.finding_ids
    END;


// ─────────────────────────────────────────
// Events 12 / 13 / 14 — Registry (add / set / rename)
// event_type baked into edge_hash via alert_sig — different ops = different edges
// ─────────────────────────────────────────

MATCH (i:ProcessInstance {id: $guid})
MATCH (reg:Registry      {id: $reg_id})
MERGE (i)-[r:MODIFIED_REGISTRY {edge_hash: $edge_hash}]->(reg)
ON CREATE SET
    r.first_seen  = $timestamp,
    r.last_seen   = $timestamp,
    r.count       = 1,
    r.max_score   = $score,
    r.finding_ids = $finding_ids,
    r.techniques  = $techniques,
    r.tactics     = $tactics,
    r.event_type  = $event_type     // "add" | "set" | "rename"
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.max_score   = CASE WHEN $score > r.max_score THEN $score ELSE r.max_score END,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + [x IN $finding_ids WHERE NOT x IN r.finding_ids]
        ELSE r.finding_ids
    END;


// ─────────────────────────────────────────
// Event 15 — CreateStreamHash (ADS)
// Minimum score enforced: 0.5
// ─────────────────────────────────────────

MATCH (i:ProcessInstance {id: $guid})
MATCH (f:File            {id: $file_id})
MERGE (i)-[r:WROTE_ADS {edge_hash: $edge_hash}]->(f)
ON CREATE SET
    r.first_seen  = $timestamp,
    r.last_seen   = $timestamp,
    r.count       = 1,
    r.max_score   = $score,
    r.finding_ids = $finding_ids,
    r.techniques  = $techniques,
    r.tactics     = $tactics,
    r.stream_name = $stream_name
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.max_score   = CASE WHEN $score > r.max_score THEN $score ELSE r.max_score END,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + [x IN $finding_ids WHERE NOT x IN r.finding_ids]
        ELSE r.finding_ids
    END;


// ─────────────────────────────────────────
// Event 22 — DNSQuery
// ─────────────────────────────────────────

MATCH (i:ProcessInstance {id: $guid})
MATCH (d:DNS             {id: $query_name})
MERGE (i)-[r:QUERIED_DNS {edge_hash: $edge_hash}]->(d)
ON CREATE SET
    r.first_seen  = $timestamp,
    r.last_seen   = $timestamp,
    r.count       = 1,
    r.max_score   = $score,
    r.finding_ids = $finding_ids,
    r.techniques  = $techniques,
    r.tactics     = $tactics
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.max_score   = CASE WHEN $score > r.max_score THEN $score ELSE r.max_score END,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + [x IN $finding_ids WHERE NOT x IN r.finding_ids]
        ELSE r.finding_ids
    END;


// ─────────────────────────────────────────
// Event 23 — FileDelete
// ─────────────────────────────────────────

MATCH (i:ProcessInstance {id: $guid})
MATCH (f:File            {id: $file_id})
MERGE (i)-[r:DELETED {edge_hash: $edge_hash}]->(f)
ON CREATE SET
    r.first_seen  = $timestamp,
    r.last_seen   = $timestamp,
    r.count       = 1,
    r.max_score   = $score,
    r.finding_ids = $finding_ids,
    r.techniques  = $techniques,
    r.tactics     = $tactics
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.max_score   = CASE WHEN $score > r.max_score THEN $score ELSE r.max_score END,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + [x IN $finding_ids WHERE NOT x IN r.finding_ids]
        ELSE r.finding_ids
    END;


// ─────────────────────────────────────────
// Event 25 — ProcessTampering
// Minimum score enforced: 0.7  — both endpoints ALWAYS created as instances
// ─────────────────────────────────────────

MATCH (attacker:ProcessInstance {id: $attacker_guid})
MATCH (victim:ProcessInstance   {id: $victim_guid})
MERGE (attacker)-[r:TAMPERED {edge_hash: $edge_hash}]->(victim)
ON CREATE SET
    r.first_seen  = $timestamp,
    r.last_seen   = $timestamp,
    r.count       = 1,
    r.max_score   = $score,
    r.finding_ids = $finding_ids,
    r.techniques  = $techniques,
    r.tactics     = $tactics,
    r.type        = $tamper_type    // e.g. "process hollowing"
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.max_score   = CASE WHEN $score > r.max_score THEN $score ELSE r.max_score END,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + [x IN $finding_ids WHERE NOT x IN r.finding_ids]
        ELSE r.finding_ids
    END;


// ═══════════════════════════════════════════════════════════════════════════════
// MAINTENANCE QUERIES  (run periodically — not at ingestion time)
// ═══════════════════════════════════════════════════════════════════════════════

// ── Prune dead low-score instances older than 24 hours
  //MATCH (p:ProcessInstance)
  //WHERE p.alive = false
  //  AND p.end_time < (timestamp() - 86400000)
  //  AND p.score < 0.3
  //DETACH DELETE p;
  //
  //// ── Compress high-frequency benign network edges (strip finding_ids, keep counts)
  //MATCH ()-[r:CONNECTED]->(:Network)
  //WHERE r.count > 100
  //  AND r.max_score < 0.2
  //SET   r.compressed = true
  //REMOVE r.finding_ids;
  //
  //// ── Remove orphan artifact nodes (no edges, not a template or user)
  //MATCH (n)
  //WHERE NOT (n)--()
  //  AND NOT n:ProcessTemplate
  //  AND NOT n:User
  //DELETE n;

// ── Update template max_seen_score hint when an instance score rises
MATCH (p:ProcessInstance)-[:INSTANCE_OF]->(t:ProcessTemplate)
WHERE p.score > t.max_seen_score
SET t.max_seen_score = p.score;


// ═══════════════════════════════════════════════════════════════════════════════
// LLM CONTEXT EXTRACTION  (run on alert — feeds LLM prompt)
// ═══════════════════════════════════════════════════════════════════════════════

// ── Extract top-5 highest-scoring attack chains (depth up to 8 hops)
//MATCH path = (entry:ProcessInstance)-[*1..8]->(terminal)
//WHERE ANY(r IN relationships(path) WHERE r.max_score > 0.5)
//  AND NONE(r IN relationships(path) WHERE r.count > 200 AND r.max_score < 0.2)
//WITH path,
//     reduce(s = 0, r IN relationships(path) | s + r.max_score) AS chain_score
//ORDER BY chain_score DESC
//LIMIT 5
//RETURN
//    [n IN nodes(path) | {
//        id:    n.id,
//        label: labels(n)[0],
//        image: n.image,
//        score: n.score
//    }] AS node_chain,
//    [r IN relationships(path) | {
//        type:       type(r),
//        first_seen: r.first_seen,
//        last_seen:  r.last_seen,
//        count:      r.count,
//        max_score:  r.max_score,
//        techniques: r.techniques,
//        tactics:    r.tactics,
//        finding_ids: r.finding_ids
//    }] AS edge_chain,
//    chain_score;
//
// ── Chain gap check tool (exposed to LLM as check_chain_gaps)
MATCH (p:ProcessInstance {id: $guid})
OPTIONAL MATCH (p)-[:CHILD_OF]->(parent_inst:ProcessInstance)
OPTIONAL MATCH (p)-[:CHILD_OF_TEMPLATE]->(parent_tmpl:ProcessTemplate)
RETURN
    p.id                      AS id,
    p.score                   AS score,
    p.image                   AS image,
    parent_inst.id            AS parent_instance_id,
    parent_tmpl.template_hash AS parent_template_hash,
    parent_tmpl.image         AS parent_template_image;
