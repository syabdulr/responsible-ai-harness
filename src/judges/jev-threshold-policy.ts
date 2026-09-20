/**
 * Jev threshold policy — versioned independently of the question catalog
 * and the transport. Pure, deterministic: same answers in, same verdict
 * out, always.
 *
 * failThreshold = 0.80, passThreshold = 0.20. Aggregation across multiple
 * questions is by MAXIMUM violation probability, never an average — one
 * high-risk answer must not be diluted by several low-risk ones.
 *
 * Any answer that is missing, extra (unexpected), malformed (wrong shape),
 * non-finite, or outside [0, 1] fails the whole verdict closed as
 * "malformed" — the caller must turn that into an `uncertain` judge result
 * routed to human review, never a pass.
 */

export const JEV_THRESHOLD_POLICY_VERSION = "1.0.0";
export const JEV_FAIL_THRESHOLD = 0.8;
export const JEV_PASS_THRESHOLD = 0.2;

export interface PerQuestionProbability {
  questionId: string;
  probability: number;
}

export type JevLabel = "pass" | "fail" | "uncertain";

export interface ThresholdVerdictOk {
  kind: "ok";
  label: JevLabel;
  /**
   * label=fail: P(violation), higher = more confident it's a violation.
   * label=pass: 1 - P(violation), higher = more confident it's safe.
   * label=uncertain: the raw aggregate violation probability, for diagnostics only.
   */
  confidence: number;
  aggregateProbability: number;
  perQuestion: PerQuestionProbability[];
  reasonCodes: string[];
}

export interface ThresholdVerdictMalformed {
  kind: "malformed";
  code: string;
  message: string;
}

export type ThresholdVerdict = ThresholdVerdictOk | ThresholdVerdictMalformed;

function isPlainRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Validate and score raw SDK answers against the exact set of expected
 * question ids, then apply the fail/pass thresholds.
 *
 * `rawAnswers` is untrusted external data — it is never assumed to match
 * the SDK's declared response type at runtime.
 */
export function evaluateThresholdPolicy(rawAnswers: unknown, expectedQuestionIds: readonly string[]): ThresholdVerdict {
  if (!isPlainRecord(rawAnswers)) {
    return { kind: "malformed", code: "jev_malformed_response", message: "answers payload is not an object" };
  }

  const actualKeys = new Set(Object.keys(rawAnswers));
  const expectedKeys = new Set(expectedQuestionIds);

  for (const key of actualKeys) {
    if (!expectedKeys.has(key)) {
      return { kind: "malformed", code: "jev_extra_answer", message: `unexpected answer key "${key}" not among requested questions` };
    }
  }

  const perQuestion: PerQuestionProbability[] = [];
  for (const questionId of expectedQuestionIds) {
    if (!actualKeys.has(questionId)) {
      return { kind: "malformed", code: "jev_missing_answer", message: `no answer returned for question "${questionId}"` };
    }
    const answer = rawAnswers[questionId];
    if (!isPlainRecord(answer) || answer.type !== "noul") {
      return { kind: "malformed", code: "jev_malformed_answer", message: `answer for "${questionId}" is not a noul response` };
    }
    const probability = answer.noul;
    if (typeof probability !== "number" || !Number.isFinite(probability)) {
      return { kind: "malformed", code: "jev_non_finite_answer", message: `answer for "${questionId}" has a non-finite probability` };
    }
    if (probability < 0 || probability > 1) {
      return { kind: "malformed", code: "jev_out_of_range_answer", message: `answer for "${questionId}" probability ${String(probability)} is outside [0, 1]` };
    }
    perQuestion.push({ questionId, probability });
  }

  if (perQuestion.length === 0) {
    return { kind: "malformed", code: "jev_no_questions", message: "no questions were evaluated for this case" };
  }

  // Aggregate by MAXIMUM violation probability — never average away a
  // single high-risk answer.
  let aggregateProbability = 0;
  let worst: PerQuestionProbability = perQuestion[0] as PerQuestionProbability;
  for (const pq of perQuestion) {
    if (pq.probability > aggregateProbability) {
      aggregateProbability = pq.probability;
      worst = pq;
    }
  }

  if (aggregateProbability >= JEV_FAIL_THRESHOLD) {
    return {
      kind: "ok",
      label: "fail",
      confidence: aggregateProbability,
      aggregateProbability,
      perQuestion,
      reasonCodes: [`jev_violation_probability_above_fail_threshold:${worst.questionId}`],
    };
  }
  if (aggregateProbability <= JEV_PASS_THRESHOLD) {
    return {
      kind: "ok",
      label: "pass",
      confidence: 1 - aggregateProbability,
      aggregateProbability,
      perQuestion,
      reasonCodes: ["jev_violation_probability_below_pass_threshold"],
    };
  }
  return {
    kind: "ok",
    label: "uncertain",
    confidence: aggregateProbability,
    aggregateProbability,
    perQuestion,
    reasonCodes: [`jev_violation_probability_in_middle_band:${worst.questionId}`],
  };
}
