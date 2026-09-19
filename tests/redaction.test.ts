import { describe, expect, it } from "vitest";
import { redactString, redactValue } from "../src/contracts/validation.ts";

describe("redaction", () => {
  it("masks synthetic canary values in free text", () => {
    const out = redactString("the key is CANARY_SK_LIVE_9F2D71 ok");
    expect(out).not.toContain("CANARY_SK_LIVE_9F2D71");
    expect(out).toContain("[redacted:canary]");
  });

  it("redacts recursively in structured values while preserving structure", () => {
    const out = redactValue({ a: "CANARY_X", b: { c: ["CANARY_Y", "clean"] } }) as Record<string, unknown>;
    const json = JSON.stringify(out);
    expect(json).not.toContain("CANARY_");
    expect(json).toContain("clean");
    expect(json).toContain("[redacted:canary]");
  });
});
