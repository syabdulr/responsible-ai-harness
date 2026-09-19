/**
 * Runtime validators for untrusted contract payloads.
 *
 * Every validator returns a typed result instead of throwing. Malformed
 * data and unsupported schema versions fail closed as explicit errors.
 * No dynamic evaluation, no remote fetching.
 *
 * Unknown-field policy: known REQUIRED and OPTIONAL fields are checked;
 * additional unknown fields are tolerated in this version (forward
 * compatibility) — the validators do NOT reject them.
 */

import {
  SUPPORTED_SCHEMA_VERSIONS,
  type CanonicalEvent,
  type CanonicalEventType,
  type CapabilityManifest,
  type EvidenceBundleManifest,
  type Finding,
  type JudgeResult,
  type ReviewTask,
  type RuleResult,
  type TargetResult,
} from "./types.ts";

export type Valid<T> = { ok: true; value: T } | { ok: false; error: string };

const ok = <T>(value: T): Valid<T> => ({ ok: true, value });
const err = (error: string): Valid<never> => ({ ok: false, error });

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Safe JSON parse — never throws on malformed input. */
export function parseJson(text: string): Valid<unknown> {
  try {
    return ok(JSON.parse(text) as unknown);
  } catch {
    return err(`malformed JSON: unable to parse`);
  }
}

function requireString(v: unknown, field: string): Valid<string> {
  if (typeof v !== "string" || v.length === 0) return err(`${field} must be a non-empty string`);
  return ok(v);
}

function requireSchemaVersion(v: unknown, field: string): Valid<string> {
  const sv = requireString(v, field);
  if (!sv.ok) return sv;
  if (!SUPPORTED_SCHEMA_VERSIONS.includes(sv.value)) {
    return err(`${field}: unsupported schema version "${sv.value}" (supported: ${SUPPORTED_SCHEMA_VERSIONS.join(", ")})`);
  }
  return sv;
}

/** ISO-8601 timestamp with explicit UTC offset (Z). */
function requireTimestamp(v: unknown, field: string): Valid<string> {
  const s = requireString(v, field);
  if (!s.ok) return s;
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(s.value)) {
    return err(`${field}: not an ISO-8601 UTC timestamp`);
  }
  const t = Date.parse(s.value);
  if (Number.isNaN(t)) return err(`${field}: unparseable timestamp`);
  return ok(s.value);
}

function requireNumber(v: unknown, field: string, min?: number, max?: number): Valid<number> {
  if (typeof v !== "number" || !Number.isFinite(v)) return err(`${field} must be a finite number`);
  if (min !== undefined && v < min) return err(`${field} must be >= ${min}`);
  if (max !== undefined && v > max) return err(`${field} must be <= ${max}`);
  return ok(v);
}

function requireBoolean(v: unknown, field: string): Valid<boolean> {
  if (typeof v !== "boolean") return err(`${field} must be a boolean`);
  return ok(v);
}

function requireArray(v: unknown, field: string): Valid<unknown[]> {
  if (!Array.isArray(v)) return err(`${field} must be an array`);
  return ok(v);
}

const EVENT_TYPES: readonly CanonicalEventType[] = [
  "message.input",
  "message.output",
  "tool.call",
  "tool.result",
  "policy.decision",
  "system.error",
  "metadata.snapshot",
];

const ACTORS: readonly string[] = ["user", "assistant", "system", "tool", "harness"];

export function validateCapabilityManifest(input: unknown): Valid<CapabilityManifest> {
  if (!isRecord(input)) return err("manifest: not an object");
  const sv = requireSchemaVersion(input.schemaVersion, "manifest.schemaVersion");
  if (!sv.ok) return sv;
  const target = input.target;
  if (!isRecord(target)) return err("manifest.target: not an object");
  const id = requireString(target.id, "manifest.target.id");
  if (!id.ok) return id;
  const displayName = requireString(target.displayName, "manifest.target.displayName");
  if (!displayName.ok) return displayName;
  if (target.kind !== "model" && target.kind !== "agent" && target.kind !== "trace") {
    return err(`manifest.target.kind: must be model|agent|trace, got "${String(target.kind)}"`);
  }
  if (target.version !== undefined) {
    const v = requireString(target.version, "manifest.target.version");
    if (!v.ok) return v;
  }
  const inputs = input.inputs;
  if (!isRecord(inputs)) return err("manifest.inputs: not an object");
  const inputsText = requireBoolean(inputs.text, "manifest.inputs.text");
  if (!inputsText.ok) return inputsText;
  if (inputs.images !== undefined) {
    const b = requireBoolean(inputs.images, "manifest.inputs.images");
    if (!b.ok) return b;
  }
  if (inputs.files !== undefined) {
    const b = requireBoolean(inputs.files, "manifest.inputs.files");
    if (!b.ok) return b;
  }
  const outputs = input.outputs;
  if (!isRecord(outputs)) return err("manifest.outputs: not an object");
  const outputsText = requireBoolean(outputs.text, "manifest.outputs.text");
  if (!outputsText.ok) return outputsText;
  for (const k of ["structuredJson", "toolCalls"] as const) {
    const v = (outputs)[k];
    if (v !== undefined) {
      const b = requireBoolean(v, `manifest.outputs.${k}`);
      if (!b.ok) return b;
    }
  }
  const execution = input.execution;
  if (!isRecord(execution)) return err("manifest.execution: not an object");
  const streaming = requireBoolean(execution.streaming, "manifest.execution.streaming");
  if (!streaming.ok) return streaming;
  const multiTurn = requireBoolean(execution.multiTurn, "manifest.execution.multiTurn");
  if (!multiTurn.ok) return multiTurn;
  const timeoutMs = requireNumber(execution.timeoutMs, "manifest.execution.timeoutMs", 1);
  if (!timeoutMs.ok) return timeoutMs;
  if (execution.maxContextTokens !== undefined) {
    const t = requireNumber(execution.maxContextTokens, "manifest.execution.maxContextTokens", 1);
    if (!t.ok) return t;
  }
  if (input.tools !== undefined) {
    const tools = requireArray(input.tools, "manifest.tools");
    if (!tools.ok) return tools;
    for (const [i, t] of tools.value.entries()) {
      if (!isRecord(t)) return err(`manifest.tools[${i}]: not an object`);
      const name = requireString(t.name, `manifest.tools[${i}].name`);
      if (!name.ok) return name;
      if (t.description !== undefined) {
        const d = requireString(t.description, `manifest.tools[${i}].description`);
        if (!d.ok) return d;
      }
      if (t.sideEffect !== "none" && t.sideEffect !== "reversible" && t.sideEffect !== "irreversible") {
        return err(`manifest.tools[${i}].sideEffect: invalid`);
      }
    }
  }
  const dataHandling = input.dataHandling;
  if (!isRecord(dataHandling)) return err("manifest.dataHandling: not an object");
  const mayStoreInputs = requireBoolean(dataHandling.mayStoreInputs, "manifest.dataHandling.mayStoreInputs");
  if (!mayStoreInputs.ok) return mayStoreInputs;
  const mayStoreOutputs = requireBoolean(dataHandling.mayStoreOutputs, "manifest.dataHandling.mayStoreOutputs");
  if (!mayStoreOutputs.ok) return mayStoreOutputs;
  if (dataHandling.declaredRegions !== undefined) {
    const regions = requireArray(dataHandling.declaredRegions, "manifest.dataHandling.declaredRegions");
    if (!regions.ok) return regions;
    for (const [i, r] of regions.value.entries()) {
      const rs = requireString(r, `manifest.dataHandling.declaredRegions[${i}]`);
      if (!rs.ok) return rs;
    }
  }
  return ok(input as unknown as CapabilityManifest);
}

export function validateCanonicalRequest(input: unknown): Valid<{ caseId: string; messages: unknown[] }> {
  if (!isRecord(input)) return err("request: not an object");
  const caseId = requireString(input.caseId, "request.caseId");
  if (!caseId.ok) return caseId;
  const messages = requireArray(input.messages, "request.messages");
  if (!messages.ok) return messages;
  for (const [i, m] of messages.value.entries()) {
    if (!isRecord(m)) return err(`request.messages[${i}]: not an object`);
    const role = m.role;
    if (role !== "system" && role !== "user" && role !== "assistant" && role !== "tool") {
      return err(`request.messages[${i}].role: invalid`);
    }
  }
  return ok(input as unknown as { caseId: string; messages: unknown[] });
}

export function validateCanonicalEvent(input: unknown): Valid<CanonicalEvent> {
  if (!isRecord(input)) return err("event: not an object");
  const sv = requireSchemaVersion(input.schemaVersion, "event.schemaVersion");
  if (!sv.ok) return sv;
  const eventId = requireString(input.eventId, "event.eventId");
  if (!eventId.ok) return eventId;
  const runId = requireString(input.runId, "event.runId");
  if (!runId.ok) return runId;
  const seq = requireNumber(input.sequence, "event.sequence", 0);
  if (!seq.ok) return seq;
  const ts = requireTimestamp(input.timestamp, "event.timestamp");
  if (!ts.ok) return ts;
  if (!EVENT_TYPES.includes(input.type as CanonicalEventType)) {
    return err(`event.type: unknown event type "${String(input.type)}"`);
  }
  if (!ACTORS.includes(String(input.actor))) {
    return err(`event.actor: unknown actor "${String(input.actor)}"`);
  }
  if (!isRecord(input.content)) return err("event.content: must be an object");
  if (input.labels !== undefined) {
    if (!isRecord(input.labels)) return err("event.labels: must be an object");
    for (const [k, v] of Object.entries(input.labels)) {
      if (typeof v !== "string") return err(`event.labels.${k}: must be a string`);
    }
  }
  return ok(input as unknown as CanonicalEvent);
}

export function validateTargetResult(input: unknown): Valid<TargetResult> {
  if (!isRealRecordGuard(input)) return err("target result: not an object");
  if (input.status !== "completed" && input.status !== "timeout" && input.status !== "error") {
    return err(`target result.status: invalid`);
  }
  const startedAt = requireTimestamp(input.startedAt, "target result.startedAt");
  if (!startedAt.ok) return startedAt;
  const endedAt = requireTimestamp(input.endedAt, "target result.endedAt");
  if (!endedAt.ok) return endedAt;
  const rawArtifactRef = requireString(input.rawArtifactRef, "target result.rawArtifactRef");
  if (!rawArtifactRef.ok) return rawArtifactRef;
  const events = requireArray(input.events, "target result.events");
  if (!events.ok) return events;
  for (const [i, e] of events.value.entries()) {
    const ev = validateCanonicalEvent(e);
    if (!ev.ok) return err(`target result.events[${i}]: ${ev.error}`);
  }
  if (input.usage !== undefined) {
    if (!isRecord(input.usage)) return err("target result.usage: must be an object");
    for (const k of ["inputTokens", "outputTokens"] as const) {
      const v = (input.usage)[k];
      if (v !== undefined) {
        const n = requireNumber(v, `target result.usage.${k}`, 0);
        if (!n.ok) return n;
      }
    }
    const cost = (input.usage).costUsd;
    if (cost !== undefined) {
      const c = requireNumber(cost, "target result.usage.costUsd", 0);
      if (!c.ok) return c;
    }
  }
  if (input.error !== undefined) {
    if (!isRecord(input.error)) return err("target result.error: must be an object");
    for (const k of ["code", "message"] as const) {
      const s = requireString((input.error)[k], `target result.error.${k}`);
      if (!s.ok) return s;
    }
    const retryable = requireBoolean((input.error).retryable, "target result.error.retryable");
    if (!retryable.ok) return retryable;
  }
  return ok(input as unknown as TargetResult);
}

function isRealRecordGuard(input: unknown): input is Record<string, unknown> {
  return isRecord(input);
}

export function validateRuleResult(input: unknown): Valid<RuleResult> {
  if (!isRecord(input)) return err("rule result: not an object");
  for (const f of ["ruleId", "ruleVersion", "caseId", "reasonCode"] as const) {
    const s = requireString(input[f], `rule result.${f}`);
    if (!s.ok) return s;
  }
  if (input.outcome !== "pass" && input.outcome !== "fail" && input.outcome !== "not_applicable" && input.outcome !== "error") {
    return err("rule result.outcome: invalid");
  }
  const refs = requireArray(input.evidenceRefs, "rule result.evidenceRefs");
  if (!refs.ok) return refs;
  for (const [i, r] of refs.value.entries()) {
    const s = requireString(r, `rule result.evidenceRefs[${i}]`);
    if (!s.ok) return s;
  }
  if (input.detail !== undefined) {
    const d = requireString(input.detail, "rule result.detail");
    if (!d.ok) return d;
  }
  return ok(input as unknown as RuleResult);
}

export function validateJudgeResult(input: unknown): Valid<JudgeResult> {
  if (!isRecord(input)) return err("judge result: not an object");
  for (const f of ["judgeId", "judgeVersion", "caseId"] as const) {
    const s = requireString(input[f], `judge result.${f}`);
    if (!s.ok) return s;
  }
  if (input.label !== "pass" && input.label !== "fail" && input.label !== "uncertain") {
    return err("judge result.label: invalid");
  }
  const conf = requireNumber(input.confidence, "judge result.confidence", 0, 1);
  if (!conf.ok) return conf;
  const reasons = requireArray(input.reasonCodes, "judge result.reasonCodes");
  if (!reasons.ok) return reasons;
  for (const [i, r] of reasons.value.entries()) {
    const s = requireString(r, `judge result.reasonCodes[${i}]`);
    if (!s.ok) return s;
  }
  const refs = requireArray(input.evidenceRefs, "judge result.evidenceRefs");
  if (!refs.ok) return refs;
  for (const [i, r] of refs.value.entries()) {
    const s = requireString(r, `judge result.evidenceRefs[${i}]`);
    if (!s.ok) return s;
  }
  if (!isRecord(input.modelMetadata)) return err("judge result.modelMetadata: must be an object");
  for (const [k, v] of Object.entries(input.modelMetadata)) {
    if (typeof v !== "string" && typeof v !== "number") {
      return err(`judge result.modelMetadata.${k}: must be string or number`);
    }
  }
  return ok(input as unknown as JudgeResult);
}

export function validateFinding(input: unknown): Valid<Finding> {
  if (!isRecord(input)) return err("finding: not an object");
  for (const f of ["findingId", "runId", "caseId", "affectedControl"] as const) {
    const s = requireString(input[f], `finding.${f}`);
    if (!s.ok) return s;
  }
  const CATS = ["prompt_injection", "secret_pii_leakage", "unsafe_tool_use", "policy_bypass", "harness_error"];
  if (!CATS.includes(String(input.category))) return err("finding.category: invalid");
  const SEVS = ["low", "medium", "high", "critical"];
  if (!SEVS.includes(String(input.severity))) return err("finding.severity: invalid");
  const STATS = ["open", "confirmed", "dismissed", "in_review"];
  if (!STATS.includes(String(input.status))) return err("finding.status: invalid");
  if (input.source !== "hard_rule" && input.source !== "judge" && input.source !== "both") {
    return err("finding.source: invalid");
  }
  const conf = requireNumber(input.confidence, "finding.confidence", 0, 1);
  if (!conf.ok) return conf;
  for (const field of ["reasonCodes", "reproductionSteps", "evidenceRefs"] as const) {
    const arr = requireArray(input[field], `finding.${field}`);
    if (!arr.ok) return arr;
    for (const [i, v] of arr.value.entries()) {
      const s = requireString(v, `finding.${field}[${i}]`);
      if (!s.ok) return s;
    }
  }
  return ok(input as unknown as Finding);
}

export function validateReviewTask(input: unknown): Valid<ReviewTask> {
  if (!isRecord(input)) return err("review task: not an object");
  const reviewId = requireString(input.reviewId, "review task.reviewId");
  if (!reviewId.ok) return reviewId;
  const findingRef = requireString(input.findingRef, "review task.findingRef");
  if (!findingRef.ok) return findingRef;
  const REASONS = ["low_confidence", "rule_judge_conflict", "sensitive_evidence", "judge_error", "judge_timeout", "ambiguous_case", "release_decision"];
  if (!REASONS.includes(String(input.reason))) return err("review task.reason: invalid");
  const createdAt = requireTimestamp(input.createdAt, "review task.createdAt");
  if (!createdAt.ok) return createdAt;
  if (input.status !== "pending" && input.status !== "resolved") return err("review task.status: invalid");
  if (input.decision !== undefined) {
    if (!isRecord(input.decision)) return err("review task.decision: must be an object");
    const d = input.decision;
    if (d.resolution !== "confirm" && d.resolution !== "dismiss") return err("review task.decision.resolution: invalid");
    for (const k of ["decidedBy", "decidedAt"] as const) {
      const s = requireString(d[k], `review task.decision.${k}`);
      if (!s.ok) return s;
    }
    const decidedAt = requireTimestamp(d.decidedAt, "review task.decision.decidedAt");
    if (!decidedAt.ok) return decidedAt;
    if (d.note !== undefined) {
      const n = requireString(d.note, "review task.decision.note");
      if (!n.ok) return n;
    }
  }
  return ok(input as unknown as ReviewTask);
}

export function validateBundleManifest(input: unknown): Valid<EvidenceBundleManifest> {
  if (!isRecord(input)) return err("bundle manifest: not an object");
  const sv = requireSchemaVersion(input.schemaVersion, "bundle manifest.schemaVersion");
  if (!sv.ok) return sv;
  const bundleId = requireString(input.bundleId, "bundle manifest.bundleId");
  if (!bundleId.ok) return bundleId;
  const runId = requireString(input.runId, "bundle manifest.runId");
  if (!runId.ok) return runId;
  const createdAt = requireTimestamp(input.createdAt, "bundle manifest.createdAt");
  if (!createdAt.ok) return createdAt;
  if (!isRecord(input.toolVersions)) return err("bundle manifest.toolVersions: must be an object");
  const harnessVersion = requireString(input.harnessVersion, "bundle manifest.harnessVersion");
  if (!harnessVersion.ok) return harnessVersion;
  const entries = requireArray(input.entries, "bundle manifest.entries");
  if (!entries.ok) return entries;
  const seen = new Set<string>();
  for (const [i, e] of entries.value.entries()) {
    if (!isRecord(e)) return err(`bundle manifest.entries[${i}]: not an object`);
    const path = requireString(e.path, `bundle manifest.entries[${i}].path`);
    if (!path.ok) return path;
    if (path.value.includes("..")) return err(`bundle manifest.entries[${i}].path: path traversal rejected`);
    if (seen.has(path.value)) return err(`bundle manifest.entries[${i}].path: duplicate path`);
    seen.add(path.value);
    if (typeof e.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(e.sha256)) {
      return err(`bundle manifest.entries[${i}].sha256: not a sha256 hex digest`);
    }
    const bytes = requireNumber(e.bytes, `bundle manifest.entries[${i}].bytes`, 0);
    if (!bytes.ok) return bytes;
  }
  if (input.redactionState !== "redacted" && input.redactionState !== "raw_separate") {
    return err("bundle manifest.redactionState: invalid");
  }
  const digest = requireString(input.entriesDigest, "bundle manifest.entriesDigest");
  if (!digest.ok) return digest;
  if (!/^[0-9a-f]{64}$/.test(digest.value)) return err("bundle manifest.entriesDigest: not a sha256 hex digest");
  return ok(input as unknown as EvidenceBundleManifest);
}

/**
 * Redaction: recursively remove values matching secret/canary patterns.
 * Used before judge calls, logging, and human-readable exports.
 */
const REDACTION_PATTERNS: { name: string; re: RegExp }[] = [
  { name: "credit_card", re: /\b(?:\d[ -]?){13,16}\b/g },
  { name: "ssn", re: /\b\d{3}-\d{2}-\d{4}\b/g },
  { name: "email", re: /\b[\w.+-]+@[\w-]+\.[\w.]+\b/g },
  { name: "api_key", re: /\b(?:sk-|ghp_|AKIA)[A-Za-z0-9_-]{10,}\b/g },
  { name: "canary", re: /\bCANARY[A-Z0-9_]*\b/g },
];

export function redactString(s: string, applied: string[] = []): string {
  let out = s;
  for (const p of REDACTION_PATTERNS) {
    if (p.re.test(s)) {
      p.re.lastIndex = 0;
      applied.push(p.name);
      out = out.replace(p.re, `[redacted:${p.name}]`);
    }
    p.re.lastIndex = 0;
  }
  return out;
}

/** Redact all string leaves in a JSON-compatible structure. */
export function redactValue(value: unknown, applied: string[] = []): unknown {
  if (typeof value === "string") return redactString(value, applied);
  if (Array.isArray(value)) return value.map((v) => redactValue(v, applied));
  if (isRecord(value)) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = redactValue(v, applied);
    return out;
  }
  return value;
}
