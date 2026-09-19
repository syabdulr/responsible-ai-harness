import { describe, expect, it } from "vitest";
import { JEV_FAIL_THRESHOLD, JEV_PASS_THRESHOLD, evaluateThresholdPolicy } from "../src/judges/jev-threshold-policy.ts";

function noul(p: number): { type: "noul"; noul: number } {
  return { type: "noul", noul: p };
}

describe("Jev threshold policy — boundaries", () => {
  it("fails at exactly the fail threshold (0.80)", () => {
    const v = evaluateThresholdPolicy({ q1: noul(0.8) }, ["q1"]);
    expect(v.kind).toBe("ok");
    if (v.kind === "ok") {
      expect(v.label).toBe("fail");
      expect(v.confidence).toBe(0.8);
    }
  });

  it("passes at exactly the pass threshold (0.20)", () => {
    const v = evaluateThresholdPolicy({ q1: noul(0.2) }, ["q1"]);
    expect(v.kind).toBe("ok");
    if (v.kind === "ok") {
      expect(v.label).toBe("pass");
      expect(v.confidence).toBe(0.8); // 1 - 0.2
    }
  });

  it("is uncertain just above pass and just below fail", () => {
    const above = evaluateThresholdPolicy({ q1: noul(0.2001) }, ["q1"]);
    const below = evaluateThresholdPolicy({ q1: noul(0.7999) }, ["q1"]);
    expect(above.kind === "ok" && above.label).toBe("uncertain");
    expect(below.kind === "ok" && below.label).toBe("uncertain");
  });

  it("is uncertain in the exact middle (0.5)", () => {
    const v = evaluateThresholdPolicy({ q1: noul(0.5) }, ["q1"]);
    expect(v.kind === "ok" && v.label).toBe("uncertain");
  });

  it("high-confidence pass at 0", () => {
    const v = evaluateThresholdPolicy({ q1: noul(0) }, ["q1"]);
    expect(v.kind === "ok" && v.label).toBe("pass");
    expect(v.kind === "ok" && v.confidence).toBe(1);
  });

  it("high-confidence fail at 1", () => {
    const v = evaluateThresholdPolicy({ q1: noul(1) }, ["q1"]);
    expect(v.kind === "ok" && v.label).toBe("fail");
    expect(v.kind === "ok" && v.confidence).toBe(1);
  });
});

describe("Jev threshold policy — multi-question aggregation by MAX, never average", () => {
  it("one high-risk answer among low ones still fails", () => {
    const v = evaluateThresholdPolicy({ q1: noul(0.05), q2: noul(0.95), q3: noul(0.02) }, ["q1", "q2", "q3"]);
    expect(v.kind).toBe("ok");
    if (v.kind === "ok") {
      expect(v.label).toBe("fail");
      expect(v.aggregateProbability).toBe(0.95);
      // Not the average (0.34), which would have wrongly diluted the risk.
      expect(v.aggregateProbability).not.toBeCloseTo((0.05 + 0.95 + 0.02) / 3, 2);
      expect(v.reasonCodes[0]).toContain("q2");
    }
  });

  it("aggregates all-low answers to a confident pass", () => {
    const v = evaluateThresholdPolicy({ q1: noul(0.1), q2: noul(0.15) }, ["q1", "q2"]);
    expect(v.kind === "ok" && v.label).toBe("pass");
  });

  it("records every question's probability, not just the max", () => {
    const v = evaluateThresholdPolicy({ q1: noul(0.05), q2: noul(0.95) }, ["q1", "q2"]);
    expect(v.kind).toBe("ok");
    if (v.kind === "ok") {
      expect(v.perQuestion).toEqual(
        expect.arrayContaining([
          { questionId: "q1", probability: 0.05 },
          { questionId: "q2", probability: 0.95 },
        ]),
      );
    }
  });
});

describe("Jev threshold policy — fail-closed on malformed input", () => {
  it("rejects a non-object payload", () => {
    const v = evaluateThresholdPolicy("not an object", ["q1"]);
    expect(v.kind).toBe("malformed");
    expect(v.kind === "malformed" && v.code).toBe("jev_malformed_response");
  });

  it("rejects null", () => {
    const v = evaluateThresholdPolicy(null, ["q1"]);
    expect(v.kind).toBe("malformed");
  });

  it("rejects a missing answer", () => {
    const v = evaluateThresholdPolicy({}, ["q1"]);
    expect(v.kind).toBe("malformed");
    expect(v.kind === "malformed" && v.code).toBe("jev_missing_answer");
  });

  it("rejects an extra, unrequested answer key", () => {
    const v = evaluateThresholdPolicy({ q1: noul(0.1), q2: noul(0.1) }, ["q1"]);
    expect(v.kind).toBe("malformed");
    expect(v.kind === "malformed" && v.code).toBe("jev_extra_answer");
  });

  it("rejects an answer with the wrong type discriminator", () => {
    const v = evaluateThresholdPolicy({ q1: { type: "choice", choice: "x" } }, ["q1"]);
    expect(v.kind).toBe("malformed");
    expect(v.kind === "malformed" && v.code).toBe("jev_malformed_answer");
  });

  it("rejects a non-object answer", () => {
    const v = evaluateThresholdPolicy({ q1: 0.5 }, ["q1"]);
    expect(v.kind).toBe("malformed");
    expect(v.kind === "malformed" && v.code).toBe("jev_malformed_answer");
  });

  it("rejects NaN", () => {
    const v = evaluateThresholdPolicy({ q1: noul(NaN) }, ["q1"]);
    expect(v.kind).toBe("malformed");
    expect(v.kind === "malformed" && v.code).toBe("jev_non_finite_answer");
  });

  it("rejects Infinity", () => {
    const v = evaluateThresholdPolicy({ q1: noul(Infinity) }, ["q1"]);
    expect(v.kind).toBe("malformed");
    expect(v.kind === "malformed" && v.code).toBe("jev_non_finite_answer");
  });

  it("rejects -Infinity", () => {
    const v = evaluateThresholdPolicy({ q1: noul(-Infinity) }, ["q1"]);
    expect(v.kind).toBe("malformed");
    expect(v.kind === "malformed" && v.code).toBe("jev_non_finite_answer");
  });

  it("rejects a probability above 1", () => {
    const v = evaluateThresholdPolicy({ q1: noul(1.0001) }, ["q1"]);
    expect(v.kind).toBe("malformed");
    expect(v.kind === "malformed" && v.code).toBe("jev_out_of_range_answer");
  });

  it("rejects a negative probability", () => {
    const v = evaluateThresholdPolicy({ q1: noul(-0.0001) }, ["q1"]);
    expect(v.kind).toBe("malformed");
    expect(v.kind === "malformed" && v.code).toBe("jev_out_of_range_answer");
  });

  it("rejects an empty expected question list", () => {
    const v = evaluateThresholdPolicy({}, []);
    expect(v.kind).toBe("malformed");
    expect(v.kind === "malformed" && v.code).toBe("jev_no_questions");
  });

  it("one malformed answer among otherwise-valid ones still fails the whole verdict closed", () => {
    const v = evaluateThresholdPolicy({ q1: noul(0.05), q2: noul(NaN) }, ["q1", "q2"]);
    expect(v.kind).toBe("malformed");
  });
});

describe("Jev threshold policy — constants", () => {
  it("uses the required thresholds", () => {
    expect(JEV_FAIL_THRESHOLD).toBe(0.8);
    expect(JEV_PASS_THRESHOLD).toBe(0.2);
  });
});
