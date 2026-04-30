// ═══════════════════════════════════════════════════════════════════════════════
// SYSMON THREAT DETECTION GRAPH — SCHEMA REFERENCE v4.0
// Matches graph_builder.py v4.0 exactly.
//
// KEY DESIGN DECISIONS
// ─────────────────────
// 1. ProcessTemplate key = sha256(image + parent_image + cmdline + user)
//    user is part of identity: powershell run by SYSTEM ≠ by jsmith
//    No separate :User node. No RAN_AS edge.
//
// 2. ProcessInstance holds ONLY operational fields:
//    id (GUID), score (sum), ghost, alive, start_time, end_time
//    NO image, cmdline, user — those live on the template via INSTANCE_OF
//
// 3. Ghost node = minimal GUID placeholder when parent never scored
//    Fields: id, ghost=true, score=0, alive=true  — NOTHING ELSE
//    No image, no start_time, no INSTANCE_OF
//    Promoted in-place when any event fires on this GUID with score > 0
//
// 4. CHILD_OF always instance → instance (ghost or full)
//    Created ONLY from Event-1 (ProcessCreate — OS spawn relationship)
//    NEVER from injection, memory access, or any other edge type
//
// 5. Score inheritance: child.score += parent.score * 0.4
//    Applied immediately on CHILD_OF creation if parent.score > 0
//    Applied retroactively to all children on ghost promotion
//    Injection / memory access targets do NOT inherit from source
//
// 6. Edge storage gate:
//    Store when: process.score > 0  OR  rel_type in ALWAYS_STORE
//    Skip when:  process.score = 0  AND rel_type NOT in ALWAYS_STORE
//    ALWAYS_STORE = {INJECTED_THREAD, ACCESSED_MEMORY, TAMPERED, TIMESTOMPED, WROTE_ADS}
//
// 7. Edge MERGE key = edge_hash (timestamp NEVER in MERGE)
//    edge_hash = sha256(src_id + rel_type + dst_id + alert_sig)
//    alert_sig = sha256(sorted techniques + tactics)
//    Same pair + same alert class → count++, total_score += score
//    Same pair + different alert  → new edge
//
// 8. ALL scores are SUMS — no max anywhere in the system
//    edge.total_score    += effective_score
//    instance.score      += effective_score
//    template.total_score += effective_score (own template only, no parent bleed)
//
// 9. Sigma score scale: integers 1–4
//    effective_score = max(sigma_score, base_weight)
//    Base weights:
//      INJECTED_THREAD 4, ACCESSED_MEMORY 3, TAMPERED 3,
//      TIMESTOMPED 2, WROTE_ADS 2, CREATED 1, CONNECTED 1, others 0
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
// NOTE: No :User constraint — user is baked into ProcessTemplate


// ─────────────────────────────────────────
// NODE — ProcessTemplate
// Always upserted on every event.
// total_score accumulates only from events belonging to THIS template.
// Parent template never receives score from child events.
// ─────────────────────────────────────────

MERGE (t:ProcessTemplate {template_hash: $template_hash})
ON CREATE SET
    t.image        = $image,            // lowercase exe path
    t.parent_image = $parent_image,     // baked into hash
    t.cmdline      = $cmdline,          // normalised (paths stripped, max 256 chars)
    t.user         = $user,             // baked into hash
    t.description  = $description,
    t.seen_count   = 1,
    t.total_score  = $score,            // sum — starts with first event's score
    t.first_seen   = $timestamp,
    t.last_seen    = $timestamp,
    p.last_updated_at = $timestamp,     // NEW
    p.cycle_resolved = false,            // NEW
    p.cycle_resolved_reason = null,      // NEW
    p.cycle_resolved_at = null           // NEW    
ON MATCH SET
    p.last_updated_at = $timestamp,
    t.seen_count   = t.seen_count + 1,
    t.last_seen    = $timestamp,
    t.total_score  = t.total_score + $score;   // always sum, never max


// ─────────────────────────────────────────
// NODE — ProcessInstance [ghost]
// Minimal placeholder for a parent GUID that has never scored.
// Children know the parent image via their own template's parent_image field.
// ─────────────────────────────────────────

MERGE (p:ProcessInstance {id: $guid})
ON CREATE SET
    p.ghost = true,
    p.score = 0,
    p.alive = true;
// NO image, NO start_time, NO INSTANCE_OF — nothing else


// ─────────────────────────────────────────
// NODE — ProcessInstance [full] — creation or ghost promotion
// Created when effective_score > 0 OR rel_type in ALWAYS_STORE.
// ─────────────────────────────────────────

MERGE (p:ProcessInstance {id: $guid})
ON CREATE SET
    p.score      = $score,
    p.ghost      = false,
    p.alive      = true,
    p.start_time = $timestamp       // from event UtcTime — NOT server receive time
ON MATCH SET
    p.score      = p.score + $score,    // always sum
    p.ghost      = false,
    p.start_time = CASE WHEN p.ghost = true THEN $timestamp ELSE p.start_time END;
// On ghost promotion: start_time is set here for the first time


// ─────────────────────────────────────────
// INSTANCE_OF — wired after full instance creation / ghost promotion
// ─────────────────────────────────────────

MATCH (p:ProcessInstance {id: $guid})
MATCH (t:ProcessTemplate {template_hash: $template_hash})
MERGE (p)-[:INSTANCE_OF]->(t);


// ─────────────────────────────────────────
// NODE — ProcessInstance — process exit (Event 5)
// ─────────────────────────────────────────

MATCH (p:ProcessInstance {id: $guid})
SET p.alive    = false,
    p.end_time = $timestamp;


// ─────────────────────────────────────────
// NODE — Artifact nodes (always on first encounter)
// ─────────────────────────────────────────

MERGE (f:File       {id: $file_id});        // TargetFilename lowercase
MERGE (n:Network    {id: $dst_ip});         // DestinationIp  lowercase
MERGE (d:DNS        {id: $query_name});     // QueryName      lowercase
MERGE (reg:Registry {id: $target_object}); // TargetObject   lowercase
MERGE (drv:Driver   {id: $sha256})
    ON CREATE SET drv.image = $image_loaded;


// ─────────────────────────────────────────
// STRUCTURAL EDGES
// ─────────────────────────────────────────

// Parent chain — always instance → instance (ghost or full)
// Created ONLY from Event-1. Never from any other event type.
MATCH (child:ProcessInstance  {id: $child_guid})
MATCH (parent:ProcessInstance {id: $parent_guid})
MERGE (child)-[:CHILD_OF]->(parent);

// Score inheritance applied in application layer after CHILD_OF is created:
//   delta = parent.score * 0.4
//   child.score += delta   (immediate)
// On ghost promotion:
//   for each child in CHILD_OF children: child.score += promoted_parent.score * 0.4


// ═══════════════════════════════════════════════════════════════════════════════
// COMPRESSED BEHAVIOUR EDGES
//
// MERGE key   = edge_hash (timestamp excluded)
// total_score = running SUM (not max)
// ON CREATE   → initialise all fields
// ON MATCH    → last_seen, count++, total_score += score, append finding_ids
//
// Storage gate (enforced in application layer before running these queries):
//   process.score > 0  OR  rel_type in ALWAYS_STORE
//
// Base weights (effective_score = max(sigma_score, base)):
//   INJECTED_THREAD  4  ALWAYS_STORE
//   ACCESSED_MEMORY  3  ALWAYS_STORE
//   TAMPERED         3  ALWAYS_STORE
//   TIMESTOMPED      2  ALWAYS_STORE
//   WROTE_ADS        2  ALWAYS_STORE
//   CREATED          1
//   CONNECTED        1
//   all others       0
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
    r.total_score = $score,
    r.finding_ids = $finding_ids,
    r.techniques  = $techniques,
    r.tactics     = $tactics
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.total_score = r.total_score + $score,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + $fids
        ELSE r.finding_ids
    END


// ─────────────────────────────────────────
// Event 2 — FileCreateTime (Timestomp)
// ALWAYS_STORE — base weight 2
// ─────────────────────────────────────────

MATCH (i:ProcessInstance {id: $guid})
MATCH (f:File            {id: $file_id})
MERGE (i)-[r:TIMESTOMPED {edge_hash: $edge_hash}]->(f)
ON CREATE SET
    r.first_seen  = $timestamp,
    r.last_seen   = $timestamp,
    r.count       = 1,
    r.total_score = $score,
    r.finding_ids = $finding_ids,
    r.techniques  = $techniques,
    r.tactics     = $tactics
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.total_score = r.total_score + $score,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + $fids
        ELSE r.finding_ids
    END


// ─────────────────────────────────────────
// Event 3 — NetworkConnect
// Stored only when process.score > 0. Base weight 1.
// ─────────────────────────────────────────

MATCH (i:ProcessInstance {id: $guid})
MATCH (n:Network         {id: $dst_ip})
MERGE (i)-[r:CONNECTED {edge_hash: $edge_hash}]->(n)
ON CREATE SET
    r.first_seen  = $timestamp,
    r.last_seen   = $timestamp,
    r.count       = 1,
    r.total_score = $score,
    r.finding_ids = $finding_ids,
    r.techniques  = $techniques,
    r.tactics     = $tactics,
    r.port        = $port,
    r.protocol    = $protocol
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.total_score = r.total_score + $score,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + $fids
        ELSE r.finding_ids
    END


// ─────────────────────────────────────────
// Event 6 — DriverLoad
// Stored only when process.score > 0. Base weight 0.
// ─────────────────────────────────────────

MATCH (i:ProcessInstance {id: $guid})
MATCH (drv:Driver        {id: $sha256})
MERGE (i)-[r:LOADED_DRIVER {edge_hash: $edge_hash}]->(drv)
ON CREATE SET
    r.first_seen  = $timestamp,
    r.last_seen   = $timestamp,
    r.count       = 1,
    r.total_score = $score,
    r.finding_ids = $finding_ids,
    r.techniques  = $techniques,
    r.tactics     = $tactics
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.total_score = r.total_score + $score,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + $fids
        ELSE r.finding_ids
    END


// ─────────────────────────────────────────
// Event 7 — ImageLoad
// Stored only when process.score > 0. Base weight 0.
// ─────────────────────────────────────────

MATCH (i:ProcessInstance {id: $guid})
MATCH (img:Driver        {id: $sha256})
MERGE (i)-[r:LOADED_IMAGE {edge_hash: $edge_hash}]->(img)
ON CREATE SET
    r.first_seen  = $timestamp,
    r.last_seen   = $timestamp,
    r.count       = 1,
    r.total_score = $score,
    r.finding_ids = $finding_ids,
    r.techniques  = $techniques,
    r.tactics     = $tactics
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.total_score = r.total_score + $score,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + $fids
        ELSE r.finding_ids
    END


// ─────────────────────────────────────────
// Event 8 — CreateRemoteThread
// ALWAYS_STORE — base weight 4
// Both endpoints scored independently. No CHILD_OF. No inheritance.
// ─────────────────────────────────────────

MATCH (src:ProcessInstance {id: $src_guid})
MATCH (tgt:ProcessInstance {id: $tgt_guid})
MERGE (src)-[r:INJECTED_THREAD {edge_hash: $edge_hash}]->(tgt)
ON CREATE SET
    r.first_seen     = $timestamp,
    r.last_seen      = $timestamp,
    r.count          = 1,
    r.total_score    = $score,
    r.finding_ids    = $finding_ids,
    r.techniques     = $techniques,
    r.tactics        = $tactics,
    r.start_function = $start_function
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.total_score = r.total_score + $score,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + $fids
        ELSE r.finding_ids
    END


// ─────────────────────────────────────────
// Event 10 — ProcessAccess
// ALWAYS_STORE — base weight 3
// Both endpoints scored independently. No CHILD_OF. No inheritance.
// ─────────────────────────────────────────

MATCH (src:ProcessInstance {id: $src_guid})
MATCH (tgt:ProcessInstance {id: $tgt_guid})
MERGE (src)-[r:ACCESSED_MEMORY {edge_hash: $edge_hash}]->(tgt)
ON CREATE SET
    r.first_seen  = $timestamp,
    r.last_seen   = $timestamp,
    r.count       = 1,
    r.total_score = $score,
    r.finding_ids = $finding_ids,
    r.techniques  = $techniques,
    r.tactics     = $tactics,
    r.access_mask = $access_mask
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.total_score = r.total_score + $score,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + $fids
        ELSE r.finding_ids
    END


// ─────────────────────────────────────────
// Event 11 — FileCreate
// Stored only when process.score > 0. Base weight 0.
// ─────────────────────────────────────────

MATCH (i:ProcessInstance {id: $guid})
MATCH (f:File            {id: $file_id})
MERGE (i)-[r:CREATED_FILE {edge_hash: $edge_hash}]->(f)
ON CREATE SET
    r.first_seen  = $timestamp,
    r.last_seen   = $timestamp,
    r.count       = 1,
    r.total_score = $score,
    r.finding_ids = $finding_ids,
    r.techniques  = $techniques,
    r.tactics     = $tactics,
    r.size        = $size
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.total_score = r.total_score + $score,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + $fids
        ELSE r.finding_ids
    END


// ─────────────────────────────────────────
// Events 12 / 13 / 14 — Registry (add / set / rename)
// Stored only when process.score > 0. Base weight 0.
// ─────────────────────────────────────────

MATCH (i:ProcessInstance {id: $guid})
MATCH (reg:Registry      {id: $reg_id})
MERGE (i)-[r:MODIFIED_REGISTRY {edge_hash: $edge_hash}]->(reg)
ON CREATE SET
    r.first_seen  = $timestamp,
    r.last_seen   = $timestamp,
    r.count       = 1,
    r.total_score = $score,
    r.finding_ids = $finding_ids,
    r.techniques  = $techniques,
    r.tactics     = $tactics,
    r.event_type  = $event_type     // "add" | "set" | "rename"
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.total_score = r.total_score + $score,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + $fids
        ELSE r.finding_ids
    END


// ─────────────────────────────────────────
// Event 15 — CreateStreamHash (ADS)
// ALWAYS_STORE — base weight 2
// ─────────────────────────────────────────

MATCH (i:ProcessInstance {id: $guid})
MATCH (f:File            {id: $file_id})
MERGE (i)-[r:WROTE_ADS {edge_hash: $edge_hash}]->(f)
ON CREATE SET
    r.first_seen  = $timestamp,
    r.last_seen   = $timestamp,
    r.count       = 1,
    r.total_score = $score,
    r.finding_ids = $finding_ids,
    r.techniques  = $techniques,
    r.tactics     = $tactics,
    r.stream_name = $stream_name
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.total_score = r.total_score + $score,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + $fids
        ELSE r.finding_ids
    END


// ─────────────────────────────────────────
// Event 22 — DNSQuery
// Stored only when process.score > 0. Base weight 0.
// ─────────────────────────────────────────

MATCH (i:ProcessInstance {id: $guid})
MATCH (d:DNS             {id: $query_name})
MERGE (i)-[r:QUERIED_DNS {edge_hash: $edge_hash}]->(d)
ON CREATE SET
    r.first_seen  = $timestamp,
    r.last_seen   = $timestamp,
    r.count       = 1,
    r.total_score = $score,
    r.finding_ids = $finding_ids,
    r.techniques  = $techniques,
    r.tactics     = $tactics
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.total_score = r.total_score + $score,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + $fids
        ELSE r.finding_ids
    END


// ─────────────────────────────────────────
// Event 23 — FileDelete
// Stored only when process.score > 0. Base weight 0.
// ─────────────────────────────────────────

MATCH (i:ProcessInstance {id: $guid})
MATCH (f:File            {id: $file_id})
MERGE (i)-[r:DELETED {edge_hash: $edge_hash}]->(f)
ON CREATE SET
    r.first_seen  = $timestamp,
    r.last_seen   = $timestamp,
    r.count       = 1,
    r.total_score = $score,
    r.finding_ids = $finding_ids,
    r.techniques  = $techniques,
    r.tactics     = $tactics
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.total_score = r.total_score + $score,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + $fids
        ELSE r.finding_ids
    END


// ─────────────────────────────────────────
// Event 25 — ProcessTampering
// ALWAYS_STORE — base weight 3
// Both endpoints scored independently. No CHILD_OF. No inheritance.
// ─────────────────────────────────────────

MATCH (attacker:ProcessInstance {id: $attacker_guid})
MATCH (victim:ProcessInstance   {id: $victim_guid})
MERGE (attacker)-[r:TAMPERED {edge_hash: $edge_hash}]->(victim)
ON CREATE SET
    r.first_seen  = $timestamp,
    r.last_seen   = $timestamp,
    r.count       = 1,
    r.total_score = $score,
    r.finding_ids = $finding_ids,
    r.techniques  = $techniques,
    r.tactics     = $tactics,
    r.type        = $tamper_type
ON MATCH SET
    r.last_seen   = $timestamp,
    r.count       = r.count + 1,
    r.total_score = r.total_score + $score,
    r.finding_ids = CASE
        WHEN size(r.finding_ids) < 20
        THEN r.finding_ids + $fids
        ELSE r.finding_ids
    END


// ═══════════════════════════════════════════════════════════════════════════════
// MAINTENANCE  (run hourly)
// ═══════════════════════════════════════════════════════════════════════════════

// Prune dead full instances older than 24h with low score
MATCH (p:ProcessInstance)
WHERE p.ghost  = false
  AND p.alive  = false
  AND p.score  < 3
  AND p.end_time < (timestamp() - 86400000)
DETACH DELETE p;

// Prune orphan artifact nodes
MATCH (n)
WHERE NOT (n)--()
  AND NOT n:ProcessTemplate
DELETE n;

// Compress high-frequency low-score network edges
MATCH ()-[r:CONNECTED]->(:Network)
WHERE r.count > 100 AND r.total_score < 3
SET   r.compressed = true
REMOVE r.finding_ids;


// ═══════════════════════════════════════════════════════════════════════════════
// LLM CONTEXT EXTRACTION  (run on alert)
// ═══════════════════════════════════════════════════════════════════════════════

// Top-5 highest-scoring attack chains (depth 1–8)
MATCH path = (entry:ProcessInstance)-[*1..8]->(terminal)
WHERE ANY(r IN relationships(path) WHERE r.total_score > 2)
  AND NONE(r IN relationships(path) WHERE r.compressed = true)
WITH path,
     reduce(s = 0, r IN relationships(path) | s + r.total_score) AS chain_score
ORDER BY chain_score DESC
LIMIT 5
RETURN
    [n IN nodes(path) | {
        id:    n.id,
        label: labels(n)[0],
        score: n.score,
        ghost: n.ghost
    }] AS node_chain,
    [r IN relationships(path) | {
        type:        type(r),
        first_seen:  r.first_seen,
        last_seen:   r.last_seen,
        count:       r.count,
        total_score: r.total_score,
        techniques:  r.techniques,
        tactics:     r.tactics,
        finding_ids: r.finding_ids
    }] AS edge_chain,
    chain_score;

// Chain gap check — LLM tool check_chain_gaps($guid)
MATCH (p:ProcessInstance {id: $guid})
OPTIONAL MATCH (p)-[:CHILD_OF]->(parent:ProcessInstance)
OPTIONAL MATCH (p)-[:INSTANCE_OF]->(t:ProcessTemplate)
RETURN
    p.id          AS id,
    p.score       AS score,
    p.ghost       AS ghost,
    t.image       AS image,
    t.user        AS user,
    parent.id     AS parent_id,
    parent.score  AS parent_score,
    parent.ghost  AS parent_ghost;
