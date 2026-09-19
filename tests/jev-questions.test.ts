import { describe, expect, it } from "vitest";
import { CATEGORY_QUESTION_IDS, JEV_QUESTIONS, JEV_QUESTION_CATALOG_VERSION, questionsForCategory } from "../src/judges/jev-questions.ts";

describe("Jev question catalog", () => {
  it("is versioned", () => {
    expect(JEV_QUESTION_CATALOG_VERSION).toBe("2.0.0");
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

  it("prompt_injection is split into two atomic questions (trust-boundary violation, and its consequence)", () => {
    expect(CATEGORY_QUESTION_IDS.prompt_injection).toEqual([
      "prompt_injection_treated_untrusted_as_authoritative_v1",
      "prompt_injection_acted_on_untrusted_instructions_v1",
    ]);
  });

  it("unsafe_tool_use is split into three atomic questions (confirmation, recipient/scope, authorization)", () => {
    expect(CATEGORY_QUESTION_IDS.unsafe_tool_use).toEqual([
      "unsafe_tool_use_missing_confirmation_v1",
      "unsafe_tool_use_wrong_recipient_or_scope_v1",
      "unsafe_tool_use_missing_authorization_v1",
    ]);
  });

  it("no question's instructions contain a compound 'or'/'and' joining independent violation types", () => {
    // Heuristic guard against re-introducing a compound question: none of
    // the current atomic questions should need "or"/", or" joining two
    // distinct checkable claims. (Prose like "recipient or scope" is one
    // claim about one action and is fine; this checks for the specific
    // multi-clause pattern the catalog used to have.)
    const compoundJoiners = [/without .*(?:confirmation|recipient|authorization).*(?:or|,).*(?:confirmation|recipient|authorization)/i];
    for (const entry of Object.values(JEV_QUESTIONS)) {
      const text = typeof entry.question.instructions === "string" ? entry.question.instructions : "";
      for (const re of compoundJoiners) {
        expect(text).not.toMatch(re);
      }
    }
  });

  it("questionsForCategory builds exactly the catalog questions for that category, keyed by id", () => {
    const qs = questionsForCategory("unsafe_tool_use");
    expect(Object.keys(qs)).toEqual(CATEGORY_QUESTION_IDS.unsafe_tool_use);
  });

  it("questionsForCategory returns an empty question set for harness_error", () => {
    expect(questionsForCategory("harness_error")).toEqual({});
  });
});
