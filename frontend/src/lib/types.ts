// Mirror of the Pydantic schemas defined in
// src/sec_recon_agent/agent/schema.py. Kept in sync by hand; the agent
// can only return shapes that pass Pydantic validation, so anything new
// here that does not exist server-side is dead code.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";

export interface CVEReference {
  cve_id: string;
  summary: string;
  cvss_v3_score: number | null;
  severity: Severity;
  exploits_public: boolean;
  affected_products: string[];
  nvd_url: string;
  // Operational signals (added when the agent calls kev_check / epss_score).
  in_kev_catalog: boolean;
  kev_due_date: string | null;
  known_ransomware_use: boolean | null;
  epss_probability: number | null;
  epss_percentile: number | null;
}

export interface AttackMitigation {
  id: string;        // M-XXXX
  name: string;
  url: string;
}

export interface AttackTechnique {
  id: string;        // T-XXXX or T-XXXX.YYY
  name: string;
  tactics: string[];
  url: string;
  mitigations: AttackMitigation[];
  related_cwes: string[];
}

// Deterministic SSVC prioritization verdict, computed server-side in
// agent/ssvc.py and stamped onto the report AFTER the model returns (the LLM
// does not produce it). Ordered most- to least-urgent.
export type SsvcDecision = "Act" | "Attend" | "Track*" | "Track";

// Where the verdict's signals came from. "evidence": every signal was read
// from a tool return captured in the run's trajectory. "mixed": at least one
// signal had no usable tool evidence and was taken from the report as the
// model wrote it (named in unverified_signals). "report": no trajectory was
// available, every signal came from the report.
export type SsvcBasis = "evidence" | "mixed" | "report";

export interface SsvcAssessment {
  decision: SsvcDecision;
  rule: string;          // stable id of the rule that fired (audit / regression)
  rationale: string;     // one-sentence human explanation
  driving_cve: string | null; // the CVE whose signals drove the report-level call
  basis?: SsvcBasis;     // optional: captures recorded before the field existed
  unverified_signals?: string[]; // "<CVE-ID>:<kev|exploit|epss|severity>"
}

// Deterministic post-run grounding verification, computed server-side in
// agent/grounding.py against the tool returns captured from the run's message
// history and stamped onto the report AFTER the model returns (same authority
// pattern as `ssvc`; the LLM does not produce it).
export type GroundingStatus = "grounded" | "suspect" | "not_evaluated";
export type GroundingClaimStatus = "supported" | "unbacked" | "mismatch" | "unverifiable";

// One non-supported claim surfaced by the verifier. `findings` carries only
// these (supported claims are counted, not listed) so the payload stays bounded.
export interface GroundingClaim {
  subject: string;       // a CVE id, an ATT&CK technique id, or "report"
  field: string;         // the report field the claim lives in (e.g. in_kev_catalog)
  status: GroundingClaimStatus;
  detail: string | null; // short evidence note (e.g. "kev_check returned in_catalog=false")
}

export interface GroundingAssessment {
  status: GroundingStatus;
  claims_checked: number;
  supported: number;
  unbacked: number;
  mismatched: number;
  unverifiable: number;
  findings: GroundingClaim[];
  truncated: boolean;
}

// Per-feed coverage honesty: what each external signal feed actually returned.
export type SignalStatus = "found" | "not_found" | "error" | "not_queried";

export interface FeedStatus {
  feed: string;          // nvd | kev | epss | exploit | osv | attack | semantic_search
  status: SignalStatus;
  detail: string | null;
}

export interface TriageReport {
  summary: string;
  severity: Severity;
  confidence: Confidence;
  recommended_action: string;
  cves: CVEReference[];
  attack_techniques: AttackTechnique[];
  reasoning_chain: string[];
  // Present on any report produced by the current backend; may be absent on
  // reports restored from older localStorage history (render defensively).
  ssvc: SsvcAssessment | null;
  signal_coverage: FeedStatus[];
  // Same defensive-render caveat: absent on pre-grounding history entries and
  // permalinks; null when the backend could not run the verifier at all.
  grounding?: GroundingAssessment | null;
}

// Token usage for one run, emitted by api/stream.py as a `usage` SSE event
// after `final`. Any field may be null when pydantic-ai does not surface it.
export interface TokenUsage {
  input_tokens: number | null;   // total input, cache traffic included
  output_tokens: number | null;
  requests: number | null;
  cache_read_tokens?: number | null;  // prompt-cache reads, priced at 0.1x input
  cache_write_tokens?: number | null; // prompt-cache writes, priced at 1.25x input
}

// One streamed agent `node` event, timestamped on arrival (client-side) so the
// observability view can draw a real waterfall instead of a synthesized one.
export interface NodeEvent {
  name: string; // pydantic-ai node class name (e.g. ModelRequestNode)
  atMs: number; // arrival offset from run start, milliseconds
}

// SSE event payload shapes emitted by api/stream.py.
export type SseEvent =
  | { type: "started"; data: { query: string } }
  | { type: "node"; data: { node: string } }
  | { type: "final"; data: TriageReport }
  | { type: "usage"; data: TokenUsage }
  | { type: "error"; data: { type: string; message: string } };

// Local history entry persisted in localStorage.
export interface HistoryEntry {
  id: string;
  query: string;
  report: TriageReport | null;
  startedAt: string; // ISO 8601
  durationMs: number | null;
  error: string | null;
  // Real per-node arrival times + token usage. Null on entries predating this
  // (older localStorage) or when the stream ended before they were captured.
  nodeEvents: NodeEvent[] | null;
  usage: TokenUsage | null;
}

// /v1/meta response - system prompt + tool inventory for the transparency view.
export interface ToolMeta {
  name: string;
  description: string;
}

export interface AgentMeta {
  system_prompt: string;
  model: string;
  tools: ToolMeta[];
}

// /v1/audit response - the tamper-evident triage audit trail. Rows are the
// digest-only projection of a TriageEvent (the opt-in plaintext fields are
// never exposed over HTTP); mirrors AuditResponse / AuditRow in api/stream.py.
export interface AuditRow {
  event_id: string;
  ts: string;
  query_sha256: string;
  query_length: number;
  report_sha256: string;
  severity: string | null;
  confidence: string | null;
  cves_count: number;
  attack_techniques_count: number;
  kev_hits: number;
  ransomware_hits: number;
  high_epss_hits: number;
  ssvc_decision: string | null;
  grounding_status: string | null;
  model: string;
  duration_ms: number;
  outcome: string;
  error_class: string | null;
  prev_event_hash: string;
  this_event_hash: string;
}

export interface AuditVerification {
  ok: boolean;
  verified_count: number;
  broken_event_id: string | null;
}

export interface AuditTrail {
  enabled: boolean;
  count: number;
  verification: AuditVerification;
  events: AuditRow[];
}
