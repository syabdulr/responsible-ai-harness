import { describe, expect, it } from "vitest";
import { validateCapabilityManifest } from "../src/contracts/validation.ts";
import type { CapabilityManifest } from "../src/contracts/types.ts";

const valid: CapabilityManifest = {
  schemaVersion: "1.0",
  target: { id: "t1", kind: "agent", displayName: "T", version: "1.0.0" },
  inputs: { text: true },
  outputs: { text: true, structuredJson: false, toolCalls: true },
  execution: { streaming: false, multiTurn: true, timeoutMs: 5000 },
  tools: [{ name: "document.read", description: "d", sideEffect: "none" }],
  dataHandling: { mayStoreInputs: false, mayStoreOutputs: true },
};

describe("capability manifest validation", () => {
  it("accepts a valid manifest", () => {
    const r = validateCapabilityManifest(valid);
    expect(r.ok).toBe(true);
  });

  it("rejects an unsupported schema version (fail closed)", () => {
    const r = validateCapabilityManifest({ ...valid, schemaVersion: "2.0" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/schema/i);
  });

  it("rejects malformed payloads (missing target)", () => {
    const r = validateCapabilityManifest({ ...valid, target: undefined });
    expect(r.ok).toBe(false);
  });

  it("rejects empty tool names", () => {
    const r = validateCapabilityManifest({ ...valid, tools: [{ name: "", description: "d", sideEffect: "none" }] });
    expect(r.ok).toBe(false);
  });

  it("rejects a missing inputs block entirely", () => {
    const rest: Record<string, unknown> = { ...valid, inputs: undefined };
    const r = validateCapabilityManifest(rest);
    expect(r.ok).toBe(false);
  });
});
