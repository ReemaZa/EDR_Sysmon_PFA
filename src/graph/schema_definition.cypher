// ─────────────────────────────────────────
// CONSTRAINTS
// ─────────────────────────────────────────

CREATE CONSTRAINT ON (n:ProcessTemplate) ASSERT n.template_hash IS UNIQUE;
CREATE CONSTRAINT ON (n:ProcessInstance) ASSERT n.id IS UNIQUE;
CREATE CONSTRAINT ON (n:File)            ASSERT n.id IS UNIQUE;
CREATE CONSTRAINT ON (n:Network)         ASSERT n.id IS UNIQUE;
CREATE CONSTRAINT ON (n:Registry)        ASSERT n.id IS UNIQUE;
CREATE CONSTRAINT ON (n:DNS)             ASSERT n.id IS UNIQUE;
CREATE CONSTRAINT ON (n:Driver)          ASSERT n.id IS UNIQUE;
CREATE CONSTRAINT ON (n:User)            ASSERT n.id IS UNIQUE;

// ─────────────────────────────────────────
// EDGES WITH FINDING_ID
// ─────────────────────────────────────────

// Event 1 — ProcessCreate with finding_id
MATCH (parent:ProcessInstance {id: $parentGUID})
MATCH (child:ProcessInstance {id: $processGUID})
MERGE (parent)-[r:CREATED {
  timestamp:   $timestamp,
  finding_ids: [$findingId],
  total_score: $total_score
}]->(child);

// Event 1 — Link ProcessInstance to ProcessTemplate
MATCH (p:ProcessInstance {id: $processGUID})
MATCH (t:ProcessTemplate {template_hash: $template_hash})
MERGE (p)-[:INSTANCE_OF]->(t);

// Event 1 — Link ProcessInstance to User
MATCH (p:ProcessInstance {id: $processGUID})
MATCH (u:User {id: $user})
MERGE (p)-[:RAN_AS]->(u);

// Event 2 — Timestomping with finding_id
MATCH (i:ProcessInstance {id: $processGUID})
MATCH (f:File {id: $fileID})
MERGE (i)-[r:TIMESTOMPED {
  timestamp:   $timestamp,
  finding_ids: [$findingId],
  total_score: $total_score
}]->(f);

// Event 3 — Network Connect with finding_id
MATCH (i:ProcessInstance {id: $processGUID})
MATCH (n:Network {id: $destinationIp})
MERGE (i)-[r:CONNECTED {
  timestamp:   $timestamp,
  port:        $destinationPort,
  protocol:    $protocol,
  finding_ids: [$findingId],
  total_score: $total_score
}]->(n);

// Event 6 — DriverLoad with finding_id
MATCH (i:ProcessInstance {id: $processGUID})
MATCH (drv:Driver {id: $sha256})
MERGE (i)-[r:LOADED_DRIVER {
  timestamp:   $timestamp,
  finding_ids: [$findingId],
  total_score: $total_score
}]->(drv);

// Event 7 — ImageLoad with finding_id
MATCH (i:ProcessInstance {id: $processGUID})
MATCH (img:Driver {id: $sha256})
MERGE (i)-[r:LOADED_IMAGE {
  timestamp:   $timestamp,
  finding_ids: [$findingId],
  total_score: $total_score
}]->(img);

// Event 8 — CreateRemoteThread with finding_id
MATCH (src:ProcessInstance {id: $sourceGUID})
MATCH (tgt:ProcessInstance {id: $targetGUID})
MERGE (src)-[r:INJECTED_THREAD {
  timestamp:      $timestamp,
  start_function: $startFunction,
  finding_ids:    [$findingId],
  total_score:    $total_score
}]->(tgt);

// Event 10 — ProcessAccess with finding_id
MATCH (src:ProcessInstance {id: $sourceGUID})
MATCH (tgt:ProcessInstance {id: $targetGUID})
MERGE (src)-[r:ACCESSED_MEMORY {
  timestamp:   $timestamp,
  access_mask: $grantedAccess,
  finding_ids: [$findingId],
  total_score: $total_score
}]->(tgt);

// Event 11 — FileCreate with finding_id
MATCH (i:ProcessInstance {id: $processGUID})
MATCH (f:File {id: $fileID})
MERGE (i)-[r:CREATED_FILE {
  timestamp:   $timestamp,
  size:        $size,
  finding_ids: [$findingId],
  total_score: $total_score
}]->(f);

// Event 12-14 — Registry with finding_id
MATCH (i:ProcessInstance {id: $processGUID})
MATCH (reg:Registry {id: $registryID})
MERGE (i)-[r:MODIFIED_REGISTRY {
  timestamp:   $timestamp,
  event_type:  $eventType,
  finding_ids: [$findingId],
  total_score: $total_score
}]->(reg);

// Event 15 — ADS with finding_id
MATCH (i:ProcessInstance {id: $processGUID})
MATCH (f:File {id: $fileID})
MERGE (i)-[r:WROTE_ADS {
  timestamp:   $timestamp,
  stream_name: $streamName,
  finding_ids: [$findingId],
  total_score: $total_score
}]->(f);

// Event 22 — DNS with finding_id
MATCH (i:ProcessInstance {id: $processGUID})
MATCH (d:DNS {id: toLower($queryName)})
MERGE (i)-[r:QUERIED_DNS {
  timestamp:   $timestamp,
  finding_ids: [$findingId],
  total_score: $total_score
}]->(d);

// Event 23 — FileDelete with finding_id
MATCH (i:ProcessInstance {id: $processGUID})
MATCH (f:File {id: $fileID})
MERGE (i)-[r:DELETED {
  timestamp:   $timestamp,
  finding_ids: [$findingId],
  total_score: $total_score
}]->(f);

// Event 25 — ProcessTampering with finding_id
MATCH (attacker:ProcessInstance {id: $attackerGUID})
MATCH (victim:ProcessInstance {id: $processGUID})
MERGE (attacker)-[r:TAMPERED {
  timestamp:   $timestamp,
  type:        $type,
  finding_ids: [$findingId],
  total_score: $total_score
}]->(victim);
