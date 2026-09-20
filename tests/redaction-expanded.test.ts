import { describe, expect, it } from "vitest";
import { findResidualRiskIndicators, redactString, redactValue } from "../src/contracts/validation.ts";

// Every value below is a synthetic sentinel — no real credential, no real
// PII. Formats mimic vendor shapes closely enough to exercise detection.
const SENTINELS: Record<string, string> = {
  jwt: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQdQw4w9WgXcQdQw4w9WgXcQ",
  bearer: "Bearer abcdEFGH12345678ijklMNOP",
  pem: "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END RSA PRIVATE KEY-----",
  github_pat: "github_pat_11ABCDEFG0abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP",
  aws_akid: "AKIAABCDEFGHIJKLMNOP",
  stripe_key: "sk_live_51ABCDEFGHIJKLMNOPQRSTUV",
  slack_token: "xoxb-1234567890-abcdefghijklmnopqrstuvwx",
  google_key: "AIzaSyD-1234567890abcdefghijklmnopqrstuv",
  phone: "415-555-0182",
  ssn: "123-45-6789",
  credit_card: "4111 1111 1111 1111",
  account_id: "account_id: acc-9F8E7D6C5B4A",
};

describe("expanded redaction — vendor/token/PII formats", () => {
  for (const [label, value] of Object.entries(SENTINELS)) {
    it(`redacts a ${label}-shaped sentinel embedded in prose`, () => {
      const out = redactString(`context before ${value} context after`);
      expect(out).not.toContain(value);
      expect(out).toContain("[redacted:");
      expect(out).toContain("context before");
      expect(out).toContain("context after");
    });
  }

  it("redacts a JWT embedded inside a Bearer header", () => {
    const out = redactString(`Authorization: Bearer ${SENTINELS.jwt}`);
    expect(out).not.toContain(SENTINELS.jwt);
  });

  it("redacts a PEM key that spans multiple lines within one string leaf", () => {
    const out = redactString(`config dump:\n${SENTINELS.pem}\nend of dump`);
    expect(out).not.toContain("PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu");
    expect(out).toContain("end of dump");
  });

  it("redacts secrets nested inside arrays and objects (transformed/embedded case)", () => {
    const nested = { a: [{ b: `token=${SENTINELS.stripe_key}` }], c: `see ${SENTINELS.aws_akid} above` };
    const redacted = JSON.stringify(redactValue(nested));
    expect(redacted).not.toContain(SENTINELS.stripe_key);
    expect(redacted).not.toContain(SENTINELS.aws_akid);
  });

  it("redacts a base64-encoded wrapper containing an embedded secret pattern only if the inner pattern itself is present as plain text", () => {
    // Encoding a secret defeats literal pattern matching by design — this
    // is exactly the "redaction is not a guarantee" case documented in
    // validation.ts. We only assert we don't regress on the PLAIN form.
    const plain = `plain ${SENTINELS.github_pat} value`;
    expect(redactString(plain)).not.toContain(SENTINELS.github_pat);
  });
});

describe("residual risk scan — second pass over already-redacted content", () => {
  it("flags a leftover key=value-shaped secret assignment even if not a known vendor prefix", () => {
    const found = findResidualRiskIndicators({ note: "token=zzz-not-a-known-format-but-still-a-secret" });
    expect(found).toContain("residual_secret_assignment");
  });

  it("flags a leftover PEM marker", () => {
    const found = findResidualRiskIndicators({ note: "-----BEGIN PRIVATE KEY-----" });
    expect(found).toContain("residual_pem_marker");
  });

  it("flags a long hex blob that could be an unrecognized secret/key", () => {
    const found = findResidualRiskIndicators({ note: "raw: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0" });
    expect(found).toContain("residual_high_entropy_hex");
  });

  it("flags a long base64 blob", () => {
    const found = findResidualRiskIndicators({ note: "blob: QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY3ODkw" });
    expect(found).toContain("residual_high_entropy_base64");
  });

  it("finds nothing for genuinely clean, already-redacted content", () => {
    const found = findResidualRiskIndicators({ note: "[redacted:api_key] was used to authenticate", caseId: "case_1", ok: true, n: 42 });
    expect(found).toEqual([]);
  });

  it("scans recursively through arrays and nested objects", () => {
    const found = findResidualRiskIndicators({ a: [{ b: { c: "password=hunter2hunter2" } }] });
    expect(found).toContain("residual_secret_assignment");
  });
});
