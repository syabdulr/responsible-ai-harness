import { describe, expect, it } from "vitest";
import {
  parseJson,
  validateBundleManifest,
  validateCanonicalEvent,
  validateCanonicalRequest,
  validateCapabilityManifest,
  validateFinding,
  validateJudgeResult,
  validateReviewTask,
  validateRuleResult,
  validateTargetResult,
} from "../src/contracts/validation.ts";
import type { CapabilityManifest, TargetResult } from "../src/contracts/types.ts";

const VALID_MANIFEST: CapabilityManifest = {
  schemaVersion: "1.0",
  target: { id: "t1", kind: "agent", displayName: "T", version: "1.0.0" },
  inputs: { text: true, images: false, files: true },
  outputs: { text: true, structuredJson: true, toolCalls: true },
  execution: { streaming: false, multiTurn: true, timeoutMs: 5000, maxContextTokens: 100000 },
  tools: [{ name: "document.read", description: "d", sideEffect: "none" }],
  dataHandling: { mayStoreInputs: false, mayStoreOutputs: true, declaredRegions: ["ca-central"] },
};

function validEvent(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: "1.0",
    eventId: "e1",
    runId: "r1",
    sequence: 1,
    timestamp: "2026-01-01T00:00:00.000Z",
    type: "message.output",
    actor: "assistant",
    content: { text: "x" },
    ...overrides,
  };
}

function validTargetResult(): TargetResult {
  return {
    status: "completed",
    startedAt: "2026-01-01T00:00:00.000Z",
    endedAt: "2026-01-01T00:00:01.000Z",
    rawArtifactRef: "mem:test",
    events: [{
      schemaVersion: "1.0", eventId: "e1", runId: "r1", sequence: 1,
      timestamp: "2026-01-01T00:00:00.000Z", type: "message.output", actor: "assistant", content: {},
    }],
  };
}

describe("capability manifest validation — every field", () => {
  it("accepts the canonical valid manifest", () => {
    expect(validateCapabilityManifest(VALID_MANIFEST).ok).toBe(true);
  });

  it("rejects unsupported schema versions", () => {
    const r = validateCapabilityManifest({ ...VALID_MANIFEST, schemaVersion: "2.0" });
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.error).toMatch(/unsupported schema version/);
  });

  it("rejects non-object input", () => {
    expect(validateCapabilityManifest("nope").ok).toBe(false);
    expect(validateCapabilityManifest(null).ok).toBe(false);
    expect(validateCapabilityManifest([1]).ok).toBe(false);
  });

  const fieldCases: Array<[string, unknown, RegExp]> = [
    ["target missing", { ...VALID_MANIFEST, target: undefined }, /target/],
    ["target.id empty", { ...VALID_MANIFEST, target: { ...VALID_MANIFEST.target, id: "" } }, /id/],
    ["target.kind invalid", { ...VALID_MANIFEST, target: { ...VALID_MANIFEST.target, kind: "robot" } }, /kind/],
    ["target.version wrong type", { ...VALID_MANIFEST, target: { ...VALID_MANIFEST.target, version: 7 } }, /version/],
    ["inputs.text missing", { ...VALID_MANIFEST, inputs: {} }, /inputs\.text/],
    ["inputs.images wrong type", { ...VALID_MANIFEST, inputs: { text: true, images: "yes" } }, /inputs\.images/],
    ["inputs.files wrong type", { ...VALID_MANIFEST, inputs: { text: true, files: 1 } }, /inputs\.files/],
    ["outputs.text missing", { ...VALID_MANIFEST, outputs: { structuredJson: true } }, /outputs\.text/],
    ["outputs.toolCalls wrong type", { ...VALID_MANIFEST, outputs: { text: true, toolCalls: "maybe" } }, /toolCalls/],
    ["execution.streaming missing", { ...VALID_MANIFEST, execution: { multiTurn: true, timeoutMs: 5 } }, /streaming/],
    ["execution.multiTurn missing", { ...VALID_MANIFEST, execution: { streaming: true, timeoutMs: 5 } }, /multiTurn/],
    ["execution.timeoutMs zero", { ...VALID_MANIFEST, execution: { ...VALID_MANIFEST.execution, timeoutMs: 0 } }, /timeoutMs/],
    ["execution.timeoutMs negative", { ...VALID_MANIFEST, execution: { ...VALID_MANIFEST.execution, timeoutMs: -5 } }, /timeoutMs/],
    ["execution.maxContextTokens bad", { ...VALID_MANIFEST, execution: { ...VALID_MANIFEST.execution, maxContextTokens: 0 } }, /maxContextTokens/],
    ["tools not array", { ...VALID_MANIFEST, tools: "doc" }, /tools/],
    ["tool missing name", { ...VALID_MANIFEST, tools: [{ description: "d", sideEffect: "none" }] }, /name/],
    ["tool bad sideEffect", { ...VALID_MANIFEST, tools: [{ name: "x", sideEffect: "sometimes" }] }, /sideEffect/],
    ["tool description wrong type", { ...VALID_MANIFEST, tools: [{ name: "x", description: 3, sideEffect: "none" }] }, /description/],
    ["dataHandling missing", { ...VALID_MANIFEST, dataHandling: undefined }, /dataHandling/],
    ["dataHandling.mayStoreInputs missing", { ...VALID_MANIFEST, dataHandling: { mayStoreOutputs: true } }, /mayStoreInputs/],
    ["dataHandling.declaredRegions wrong element", { ...VALID_MANIFEST, dataHandling: { mayStoreInputs: false, mayStoreOutputs: true, declaredRegions: [42] } }, /declaredRegions/],
  ];
  for (const [label, input, re] of fieldCases) {
    it(`rejects ${label}`, () => {
      const r = validateCapabilityManifest(input);
      expect(r.ok, label).toBe(false);
      expect(r.ok === false && r.error).toMatch(re);
    });
  }

  it("unknown top-level fields are tolerated (documented forward-compat policy) but validated nested fields still enforced", () => {
    const r = validateCapabilityManifest({ ...VALID_MANIFEST, futureField: { anything: true } });
    expect(r.ok).toBe(true); // documented policy: unknown fields tolerated at v1.0
  });
});

describe("CanonicalEvent validation", () => {
  it("accepts a valid event incl. optional labels", () => {
    expect(validateCanonicalEvent(validEvent({ labels: { env: "test" } })).ok).toBe(true);
  });
  const cases: Array<[string, Record<string, unknown>]> = [
    ["bad schema version", { schemaVersion: "0.9" }],
    ["empty eventId", { eventId: "" }],
    ["empty runId", { runId: "" }],
    ["negative sequence", { sequence: -1 }],
    ["non-number sequence", { sequence: "1" }],
    ["naive timestamp", { timestamp: "2026-01-01T00:00:00" }],
    ["date-only timestamp", { timestamp: "2026-01-01" }],
    ["unparseable timestamp", { timestamp: "2026-13-45T99:00:00.000Z" }],
    ["unknown event type", { type: "sparkle" }],
    ["unknown actor", { actor: "intruder" }],
    ["content not object", { content: "text" }],
    ["labels wrong value type", { labels: { env: 1 } }],
    ["labels not object", { labels: ["x"] }],
  ];
  for (const [label, overrides] of cases) {
    it(`rejects ${label}`, () => {
      expect(validateCanonicalEvent(validEvent(overrides)).ok, label).toBe(false);
    });
  }
});

describe("CanonicalRequest validation", () => {
  const base = { caseId: "c1", messages: [{ role: "user", content: "hi" }] };
  it("accepts valid request with all roles", () => {
    for (const role of ["system", "user", "assistant", "tool"]) {
      expect(validateCanonicalRequest({ caseId: "c", messages: [{ role, content: "x" }] }).ok, role).toBe(true);
    }
  });
  const cases: Array<[string, unknown]> = [
    ["empty caseId", { ...base, caseId: "" }],
    ["missing messages", { caseId: "c" }],
    ["messages not array", { ...base, messages: "hi" }],
    ["message not object", { ...base, messages: ["hi"] }],
    ["bad role", { ...base, messages: [{ role: "boss", content: "x" }] }],
  ];
  for (const [label, input] of cases) {
    it(`rejects ${label}`, () => {
      expect(validateCanonicalRequest(input).ok, label).toBe(false);
    });
  }
});

describe("TargetResult validation", () => {
  it("accepts valid result with usage + error variants", () => {
    expect(validateTargetResult(validTargetResult()).ok).toBe(true);
    expect(
      validateTargetResult({ ...validTargetResult(), usage: { inputTokens: 5, outputTokens: 6, costUsd: 0.1 } }).ok,
    ).toBe(true);
    expect(
      validateTargetResult({ ...validTargetResult(), status: "error", error: { code: "e", message: "m", retryable: false } }).ok,
    ).toBe(true);
  });
  const cases: Array<[string, unknown]> = [
    ["bad status", { ...validTargetResult(), status: "partial" }],
    ["missing startedAt", { ...validTargetResult(), startedAt: undefined }],
    ["naive endedAt", { ...validTargetResult(), endedAt: "2026-01-01T00:00:01" }],
    ["empty rawArtifactRef", { ...validTargetResult(), rawArtifactRef: "" }],
    ["events not array", { ...validTargetResult(), events: {} }],
    ["invalid nested event", { ...validTargetResult(), events: [{ bogus: 1 }] }],
    ["usage negative tokens", { ...validTargetResult(), usage: { inputTokens: -1 } }],
    ["usage cost negative", { ...validTargetResult(), usage: { costUsd: -0.5 } }],
    ["error missing retryable", { ...validTargetResult(), status: "error", error: { code: "e", message: "m" } }],
    ["error code empty", { ...validTargetResult(), status: "error", error: { code: "", message: "m", retryable: false } }],
  ];
  for (const [label, input] of cases) {
    it(`rejects ${label}`, () => {
      expect(validateTargetResult(input).ok, label).toBe(false);
    });
  }
});

describe("RuleResult / JudgeResult / Finding / ReviewTask validation", () => {
  it("rule result round trip", () => {
    const good = { ruleId: "r", ruleVersion: "1", caseId: "c", outcome: "pass", reasonCode: "ok", evidenceRefs: ["e"] };
    expect(validateRuleResult(good).ok).toBe(true);
    expect(validateRuleResult({ ...good, outcome: "maybe" }).ok).toBe(false);
    expect(validateRuleResult({ ...good, evidenceRefs: [1] }).ok).toBe(false);
    expect(validateRuleResult({ ...good, detail: 3 }).ok).toBe(false);
  });

  it("judge result round trip", () => {
    const good = {
      judgeId: "j", judgeVersion: "1", caseId: "c", label: "pass", confidence: 0.5,
      reasonCodes: ["a"], evidenceRefs: ["e"], modelMetadata: {},
    };
    expect(validateJudgeResult(good).ok).toBe(true);
    expect(validateJudgeResult({ ...good, label: "maybe" }).ok).toBe(false);
    expect(validateJudgeResult({ ...good, confidence: 1.5 }).ok).toBe(false);
    expect(validateJudgeResult({ ...good, confidence: -0.1 }).ok).toBe(false);
    expect(validateJudgeResult({ ...good, reasonCodes: "a" }).ok).toBe(false);
  });

  it("finding round trip", () => {
    const good = {
      findingId: "f", runId: "r", caseId: "c", category: "prompt_injection", severity: "high",
      status: "open", confidence: 0.9, affectedControl: "C", reasonCodes: ["x"],
      reproductionSteps: ["s"], evidenceRefs: ["e"], source: "hard_rule",
    };
    expect(validateFinding(good).ok).toBe(true);
    expect(validateFinding({ ...good, category: "weird" }).ok).toBe(false);
    expect(validateFinding({ ...good, severity: "meh" }).ok).toBe(false);
    expect(validateFinding({ ...good, source: "oracle" }).ok).toBe(false);
  });

  it("review task round trip", () => {
    const good = {
      reviewId: "rv", findingRef: "f", reason: "ambiguous_case",
      createdAt: "2026-01-01T00:00:00.000Z", status: "pending",
    };
    expect(validateReviewTask(good).ok).toBe(true);
    expect(validateReviewTask({ ...good, reason: "vibes" }).ok).toBe(false);
    expect(validateReviewTask({ ...good, status: "in_progress" }).ok).toBe(false);
    expect(validateReviewTask({ ...good, createdAt: "Jan 1 2026" }).ok).toBe(false);
  });
});

describe("parseJson", () => {
  it("parses valid JSON and rejects malformed", () => {
    expect(parseJson('{"a":1}').ok).toBe(true);
    expect(parseJson("{ nope").ok).toBe(false);
  });
});

describe("bundle manifest schema validation", () => {
  const good = {
    schemaVersion: "1.0",
    bundleId: "b",
    runId: "r",
    createdAt: "2026-01-01T00:00:00.000Z",
    toolVersions: {},
    harnessVersion: "0.1.0",
    entries: [{ path: "a.json", sha256: "0".repeat(64), bytes: 1 }],
    redactionState: "redacted",
    entriesDigest: "1".repeat(64),
  };
  it("accepts a valid manifest", () => {
    expect(validateBundleManifest(good).ok).toBe(true);
  });
  const cases: Array<[string, unknown]> = [
    ["bad version", { ...good, schemaVersion: "2.0" }],
    ["empty bundleId", { ...good, bundleId: "" }],
    ["bad createdAt", { ...good, createdAt: "yesterday" }],
    ["toolVersions not object", { ...good, toolVersions: [] }],
    ["entries not array", { ...good, entries: {} }],
    ["entry sha not hex64", { ...good, entries: [{ path: "a", sha256: "zz", bytes: 1 }] }],
    ["entry bytes negative", { ...good, entries: [{ path: "a", sha256: "0".repeat(64), bytes: -1 }] }],
    ["digest not hex64", { ...good, entriesDigest: "nope" }],
    ["bad redactionState", { ...good, redactionState: "clean" }],
  ];
  for (const [label, input] of cases) {
    it(`rejects ${label}`, () => {
      expect(validateBundleManifest(input).ok, label).toBe(false);
    });
  }
});

describe("unknown-field policy is documented, not silent", () => {
  it("extra fields do not crash validators (forward compat) — v1.0 policy", () => {
    const r = validateCanonicalEvent(validEvent({ extra: "field" }));
    expect(r.ok).toBe(true);
  });
});
