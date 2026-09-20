/**
 * Fake `JevClient` for tests. Zero network, zero SDK. Scripted responses
 * only. Records call count so tests can assert one-attempt/no-retry
 * behavior at the orchestration layer.
 */

import type { JevClient, JevTransportCallOptions, JevTransportRequest, JevTransportResult } from "../../src/judges/jev-transport.ts";

export type ScriptedOutcome =
  | { kind: "result"; result: JevTransportResult }
  | { kind: "throw"; error: Error };

export class FakeJevClient implements JevClient {
  calls: JevTransportRequest[] = [];
  private readonly script: ScriptedOutcome[];
  private cursor = 0;

  constructor(script: ScriptedOutcome[]) {
    this.script = script;
  }

  systemOne(request: JevTransportRequest, _options: JevTransportCallOptions): Promise<JevTransportResult> {
    void _options;
    this.calls.push(request);
    const outcome = this.script[this.cursor];
    this.cursor += 1;
    if (outcome === undefined) {
      throw new Error("FakeJevClient: script exhausted");
    }
    if (outcome.kind === "throw") {
      return Promise.reject(outcome.error);
    }
    return Promise.resolve(outcome.result);
  }
}

/** Build a scripted noul answer set for `{questionId: probability}`. */
export function noulAnswers(probs: Record<string, number>): Record<string, { type: "noul"; noul: number }> {
  const answers: Record<string, { type: "noul"; noul: number }> = {};
  for (const [id, p] of Object.entries(probs)) {
    answers[id] = { type: "noul", noul: p };
  }
  return answers;
}

export function fakeResult(answers: unknown, overrides: Partial<Omit<JevTransportResult, "answers">> = {}): JevTransportResult {
  return {
    model: overrides.model ?? "jev-latest",
    answers,
    usage: overrides.usage ?? { inputTokens: 10, outputTokens: 5 },
    latencyMs: overrides.latencyMs ?? 42,
  };
}
