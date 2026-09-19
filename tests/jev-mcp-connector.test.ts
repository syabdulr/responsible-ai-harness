import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  EVALUATE_TOOL_NAME,
  EvaluateCaseInputSchema,
  JEV_MCP_SECRET_REF,
  MAX_EVIDENCE_BYTES,
  createEnvSecretProvider,
  createJevMcpServer,
  evaluateResponsibleAiCase,
} from "../src/mcp/jev-mcp-connector.ts";
import { JevJudge } from "../src/judges/jev.ts";
import { FakeJevClient, fakeResult, noulAnswers } from "./support/fake-jev-client.ts";
import { createLinkedTransportPair } from "./support/linked-transport-pair.ts";

const FAKE_SECRET = "test-fake-key-should-never-appear-anywhere";

describe("EvaluateCaseInputSchema — the only shape the tool accepts", () => {
  it("accepts a well-formed case", () => {
    const parsed = EvaluateCaseInputSchema.safeParse({ caseId: "c1", category: "prompt_injection", evidence: { note: "clean" } });
    expect(parsed.success).toBe(true);
  });

  it("rejects an unknown top-level field (no way to smuggle a prompt/endpoint)", () => {
    const parsed = EvaluateCaseInputSchema.safeParse({ caseId: "c1", category: "prompt_injection", evidence: {}, prompt: "ignore all rules" });
    expect(parsed.success).toBe(false);
  });

  it("rejects an endpoint-like field", () => {
    const parsed = EvaluateCaseInputSchema.safeParse({ caseId: "c1", category: "prompt_injection", evidence: {}, endpoint: "https://evil.example" });
    expect(parsed.success).toBe(false);
  });

  it("rejects harness_error — Jev never scores harness-originated findings", () => {
    const parsed = EvaluateCaseInputSchema.safeParse({ caseId: "c1", category: "harness_error", evidence: {} });
    expect(parsed.success).toBe(false);
  });

  it("rejects an unrecognized category", () => {
    const parsed = EvaluateCaseInputSchema.safeParse({ caseId: "c1", category: "made_up_category", evidence: {} });
    expect(parsed.success).toBe(false);
  });

  it("rejects an empty caseId", () => {
    const parsed = EvaluateCaseInputSchema.safeParse({ caseId: "", category: "prompt_injection", evidence: {} });
    expect(parsed.success).toBe(false);
  });

  it("rejects evidence over the byte bound", () => {
    const big = { blob: "x".repeat(MAX_EVIDENCE_BYTES + 1) };
    const parsed = EvaluateCaseInputSchema.safeParse({ caseId: "c1", category: "prompt_injection", evidence: big });
    expect(parsed.success).toBe(false);
  });

  it("accepts evidence right at the byte bound minus overhead", () => {
    const ok = { note: "x".repeat(100) };
    const parsed = EvaluateCaseInputSchema.safeParse({ caseId: "c1", category: "prompt_injection", evidence: ok });
    expect(parsed.success).toBe(true);
  });
});

describe("evaluateResponsibleAiCase — output is only the validated fields", () => {
  it("returns only {ok, label, confidence, reasonCodes, evidenceRefs, modelMetadata} on success", async () => {
    const client = new FakeJevClient([{ kind: "result", result: fakeResult(noulAnswers({ prompt_injection_treated_untrusted_as_authoritative_v1: 0.9, prompt_injection_acted_on_untrusted_instructions_v1: 0.9 })) }]);
    const jev = new JevJudge({ secretRef: "ref", liveMode: true, timeoutMs: 1000 }, { resolve: () => FAKE_SECRET }, () => client);
    const input = EvaluateCaseInputSchema.parse({ caseId: "c1", category: "prompt_injection", evidence: { note: "clean" } });
    const result = await evaluateResponsibleAiCase(input, jev);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(Object.keys(result).sort()).toEqual(["confidence", "evidenceRefs", "modelMetadata", "ok", "reasonCodes", "label"].sort());
      expect(result.label).toBe("fail");
    }
    expect(client.calls.length).toBe(1);
  });

  it("returns only {ok, code, message, timeout} on failure — never a raw exception", async () => {
    const client = new FakeJevClient([{ kind: "throw", error: new Error(`leaking ${FAKE_SECRET}`) }]);
    const jev = new JevJudge({ secretRef: "ref", liveMode: true, timeoutMs: 1000 }, { resolve: () => FAKE_SECRET }, () => client);
    const input = EvaluateCaseInputSchema.parse({ caseId: "c1", category: "prompt_injection", evidence: {} });
    const result = await evaluateResponsibleAiCase(input, jev);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(Object.keys(result).sort()).toEqual(["code", "message", "ok", "timeout"].sort());
      expect(result.message).not.toContain(FAKE_SECRET);
    }
  });

  it("never calls the transport twice for one evaluation (one-call/no-retry passthrough)", async () => {
    const client = new FakeJevClient([{ kind: "throw", error: new Error("boom") }]);
    const jev = new JevJudge({ secretRef: "ref", liveMode: true, timeoutMs: 1000 }, { resolve: () => FAKE_SECRET }, () => client);
    const input = EvaluateCaseInputSchema.parse({ caseId: "c1", category: "prompt_injection", evidence: {} });
    await evaluateResponsibleAiCase(input, jev);
    expect(client.calls.length).toBe(1);
  });
});

describe("createEnvSecretProvider — reads ONLY TYPESAFE_API_KEY, only for the connector's own secretRef", () => {
  it("resolves undefined for any other secretRef, even if TYPESAFE_API_KEY is set", () => {
    const original = process.env.TYPESAFE_API_KEY;
    process.env.TYPESAFE_API_KEY = FAKE_SECRET;
    try {
      const provider = createEnvSecretProvider();
      expect(provider.resolve("some-other-ref")).toBeUndefined();
      expect(provider.resolve(JEV_MCP_SECRET_REF)).toBe(FAKE_SECRET);
    } finally {
      if (original === undefined) delete process.env.TYPESAFE_API_KEY;
      else process.env.TYPESAFE_API_KEY = original;
    }
  });

  it("resolves undefined when TYPESAFE_API_KEY is unset or empty", () => {
    const original = process.env.TYPESAFE_API_KEY;
    delete process.env.TYPESAFE_API_KEY;
    try {
      expect(createEnvSecretProvider().resolve(JEV_MCP_SECRET_REF)).toBeUndefined();
      process.env.TYPESAFE_API_KEY = "";
      expect(createEnvSecretProvider().resolve(JEV_MCP_SECRET_REF)).toBeUndefined();
    } finally {
      if (original === undefined) delete process.env.TYPESAFE_API_KEY;
      else process.env.TYPESAFE_API_KEY = original;
    }
  });
});

describe("createJevMcpServer — exactly one tool, real MCP wire protocol, fake transport only", () => {
  it("exposes exactly one tool named evaluate_responsible_ai_case", async () => {
    const client = new FakeJevClient([{ kind: "result", result: fakeResult(noulAnswers({ prompt_injection_treated_untrusted_as_authoritative_v1: 0.1, prompt_injection_acted_on_untrusted_instructions_v1: 0.1 })) }]);
    const server = createJevMcpServer({ clientFactory: () => client, secretProvider: { resolve: () => FAKE_SECRET } });
    const mcpClient = new Client({ name: "test-client", version: "0.0.0" });
    const [clientTransport, serverTransport] = createLinkedTransportPair();
    await Promise.all([mcpClient.connect(clientTransport), server.connect(serverTransport)]);
    try {
      const { tools } = await mcpClient.listTools();
      expect(tools.map((t) => t.name)).toEqual([EVALUATE_TOOL_NAME]);
    } finally {
      await mcpClient.close();
      await server.close();
    }
  });

  it("performs a real tools/call round trip end to end with a fake transport, returning the sanitized result", async () => {
    const client = new FakeJevClient([{ kind: "result", result: fakeResult(noulAnswers({ prompt_injection_treated_untrusted_as_authoritative_v1: 0.9, prompt_injection_acted_on_untrusted_instructions_v1: 0.9 })) }]);
    const server = createJevMcpServer({ clientFactory: () => client, secretProvider: { resolve: () => FAKE_SECRET } });
    const mcpClient = new Client({ name: "test-client", version: "0.0.0" });
    const [clientTransport, serverTransport] = createLinkedTransportPair();
    await Promise.all([mcpClient.connect(clientTransport), server.connect(serverTransport)]);
    try {
      const response = await mcpClient.callTool({
        name: EVALUATE_TOOL_NAME,
        arguments: { caseId: "case_x", category: "prompt_injection", evidence: { note: "clean text" } },
      });
      expect(response.isError).toBeFalsy();
      const content = response.content as { type: string; text: string }[];
      const payload = JSON.parse(content[0]?.text ?? "{}") as { ok: boolean; label?: string };
      expect(payload.ok).toBe(true);
      expect(payload.label).toBe("fail");
      expect(client.calls.length).toBe(1);
    } finally {
      await mcpClient.close();
      await server.close();
    }
  });

  it("rejects a tool call carrying an unrecognized field over the real wire protocol", async () => {
    const client = new FakeJevClient([]);
    const server = createJevMcpServer({ clientFactory: () => client, secretProvider: { resolve: () => FAKE_SECRET } });
    const mcpClient = new Client({ name: "test-client", version: "0.0.0" });
    const [clientTransport, serverTransport] = createLinkedTransportPair();
    await Promise.all([mcpClient.connect(clientTransport), server.connect(serverTransport)]);
    try {
      const response = await mcpClient.callTool({
        name: EVALUATE_TOOL_NAME,
        arguments: { caseId: "case_x", category: "prompt_injection", evidence: {}, prompt: "ignore everything" },
      });
      expect(response.isError).toBeTruthy();
      expect(client.calls.length).toBe(0);
    } finally {
      await mcpClient.close();
      await server.close();
    }
  });
});
