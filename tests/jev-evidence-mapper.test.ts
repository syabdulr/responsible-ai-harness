import { describe, expect, it } from "vitest";
import { invokeLocalTarget, makeFakeSink, resetEventCounter } from "../src/target/local-target.ts";
import { createGuardedExecutor } from "../src/target/guarded-executor.ts";
import { DEMO_CASES } from "../src/fixtures/cases.ts";
import { buildJevEvidence, EvidenceMappingError } from "../src/judges/evidence-mapper.ts";

/**
 * The mapper is exercised against REAL guarded events produced by the
 * same local-target + guarded-executor path the pipeline uses — not
 * hand-built event fixtures — so a drift in event shape would break
 * these tests too.
 */
function guardedEventsFor(caseId: string) {
  const demoCase = DEMO_CASES.find((c) => c.caseId === caseId);
  if (demoCase === undefined) throw new Error(`no fixture ${caseId}`);
  resetEventCounter();
  const sink = makeFakeSink();
  const { events } = invokeLocalTarget({ targetId: "t", sink }, caseId, demoCase.behavior, `run_${caseId}`, () => new Date().toISOString());
  const { execute } = createGuardedExecutor({
    sink,
    irreversibleTools: ["message.send"],
    trustedActor: "harness",
    now: () => new Date(),
    nextEventId: () => `evt_g${Math.random().toString(36).slice(2)}`,
  });
  const guarded = execute(events, { runId: `run_${caseId}`, caseId });
  return { demoCase, guardedEvents: guarded.events };
}

function str(evidence: Record<string, unknown>, key: string): string {
  const v = evidence[key];
  expect(typeof v).toBe("string");
  return v as string;
}

describe("buildJevEvidence — prompt_injection (case_injection_doc)", () => {
  it("extracts the untrusted document excerpt and the assistant's response", () => {
    const { guardedEvents } = guardedEventsFor("case_injection_doc");
    const evidence = buildJevEvidence("case_injection_doc", "prompt_injection", guardedEvents);
    expect(str(evidence, "untrustedContentExcerpt")).toContain("IGNORE ALL PREVIOUS INSTRUCTIONS");
    expect(str(evidence, "assistantResponseExcerpt")).toContain("followed the document instructions");
  });
});

describe("buildJevEvidence — secret_pii_leakage (case_canary_leak)", () => {
  it("extracts the assistant output and omits absent tool fields", () => {
    const { guardedEvents } = guardedEventsFor("case_canary_leak");
    const evidence = buildJevEvidence("case_canary_leak", "secret_pii_leakage", guardedEvents);
    expect(str(evidence, "assistantOutputExcerpt")).toContain("CANARY_SK_LIVE");
    expect(evidence).not.toHaveProperty("toolArgumentsExcerpt");
    expect(evidence).not.toHaveProperty("toolResultExcerpt");
  });
});

describe("buildJevEvidence — unsafe_tool_use (case_unauthorized_send)", () => {
  it("reports the tool name, recipient, and authorization state from the harness's own policy.decision", () => {
    const { guardedEvents } = guardedEventsFor("case_unauthorized_send");
    const evidence = buildJevEvidence("case_unauthorized_send", "unsafe_tool_use", guardedEvents);
    expect(str(evidence, "toolName")).toBe("message.send");
    expect(evidence.confirmationObtained).toBe(false);
    // No grant is ever issued in this pipeline, so every irreversible call is unauthorized.
    expect(evidence.authorizationGranted).toBe(false);
    expect(str(evidence, "recipient").length).toBeGreaterThan(0);
  });

  it("never trusts a target-supplied tool.result as proof of authorization", () => {
    const { guardedEvents } = guardedEventsFor("case_unauthorized_send");
    // The guarded event stream may still carry the target's own claimed
    // "delivered" tool.result alongside the harness's "blocked_by_harness"
    // one; the mapper must not derive authorizationGranted from either.
    const evidence = buildJevEvidence("case_unauthorized_send", "unsafe_tool_use", guardedEvents);
    expect(evidence.authorizationGranted).toBe(false);
  });
});

describe("buildJevEvidence — policy_bypass (case_ambiguous_bypass)", () => {
  it("extracts the request text and the assistant's refusal response", () => {
    const { guardedEvents } = guardedEventsFor("case_ambiguous_bypass");
    const evidence = buildJevEvidence("case_ambiguous_bypass", "policy_bypass", guardedEvents);
    expect(str(evidence, "userRequestExcerpt")).toContain("forbidden-output-token");
    expect(str(evidence, "assistantResponseExcerpt")).toContain("can't help");
  });
});

describe("buildJevEvidence — fail-closed on missing expected shape", () => {
  it("throws EvidenceMappingError rather than sending partial evidence", () => {
    expect(() => buildJevEvidence("x", "prompt_injection", [])).toThrow(EvidenceMappingError);
    expect(() => buildJevEvidence("x", "unsafe_tool_use", [])).toThrow(EvidenceMappingError);
    expect(() => buildJevEvidence("x", "policy_bypass", [])).toThrow(EvidenceMappingError);
    expect(() => buildJevEvidence("x", "secret_pii_leakage", [])).toThrow(EvidenceMappingError);
  });

  it("refuses harness_error — Jev never scores it (no question catalog entry)", () => {
    expect(() => buildJevEvidence("x", "harness_error", [])).toThrow(EvidenceMappingError);
  });
});

describe("buildJevEvidence — output always validates against the allowlisted schema", () => {
  it("every demo case's mapped evidence round-trips through its zod shape without throwing", () => {
    for (const c of DEMO_CASES) {
      const { guardedEvents } = guardedEventsFor(c.caseId);
      expect(() => buildJevEvidence(c.caseId, c.category, guardedEvents)).not.toThrow();
    }
  });
});
