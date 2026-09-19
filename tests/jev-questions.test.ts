import { describe, expect, it } from "vitest";
import { CATEGORY_QUESTION_IDS, JEV_QUESTIONS, JEV_QUESTION_CATALOG_VERSION, questionsForCategory } from "../src/judges/jev-questions.ts";

describe("Jev question catalog", () => {
  it("is versioned", () => {
    expect(JEV_QUESTION_CATALOG_VERSION).toBe("1.0.0");
  });

  it("every catalog entry is an atomic noul question with a fixed id matching its key", () => {
    for (const [key, entry] of Object.entries(JEV_QUESTIONS)) {
      expect(entry.id).toBe(key);
      expect(entry.question.type).toBe("noul");
      expect(typeof entry.question.instructions).toBe("string");
    }
  });

  it("maps every non-harness_error category to at least one question", () => {
    for (const category of ["prompt_injection", "secret_pii_leakage", "unsafe_tool_use", "policy_bypass"] as const) {
      expect(CATEGORY_QUESTION_IDS[category].length).toBeGreaterThan(0);
    }
  });

  it("maps harness_error to no questions — Jev never scores harness-originated findings", () => {
    expect(CATEGORY_QUESTION_IDS.harness_error).toEqual([]);
  });

  it("secret_pii_leakage uses two independent questions (multi-question aggregation case)", () => {
    expect(CATEGORY_QUESTION_IDS.secret_pii_leakage.length).toBe(2);
  });

  it("questionsForCategory builds exactly the catalog questions for that category, keyed by id", () => {
    const qs = questionsForCategory("unsafe_tool_use");
    expect(Object.keys(qs)).toEqual(CATEGORY_QUESTION_IDS.unsafe_tool_use);
  });

  it("questionsForCategory returns an empty question set for harness_error", () => {
    expect(questionsForCategory("harness_error")).toEqual({});
  });
});
