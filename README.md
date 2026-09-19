# Responsible AI Harness

A model-agnostic, Jev-first assessment harness for testing AI models and agents against security and policy requirements.

> **MVP posture:** assessment only. The harness observes, tests, scores, and reports. It does not block production requests or take enforcement actions. A versioned enforcement interface is reserved for later use.

## Product principles

- **Model-agnostic at the edges:** any model, agent, or recorded trace can be assessed through a small adapter contract.
- **Jev-first at the core:** Jev is the default low-cost judge for high-volume classification and triage, but it is a replaceable scoring plugin rather than a hard dependency.
- **Deterministic where policy is hard:** explicit rules decide requirements that must not vary between model calls.
- **Evidence before verdicts:** every finding points to normalized events, rule outputs, judge results, and the exact test version that produced it.
- **Humans resolve ambiguity:** low-confidence or disputed findings go to a review queue.
- **Thin adapters, stable control plane:** provider-specific code stays at the boundary. Run orchestration, evidence, findings, and review remain provider-neutral.

## MVP scope

### In scope

1. Universal REST target adapter
2. JSONL trace upload
3. Capability manifest
4. Normalized event and evidence model
5. Four initial test plugins:
   - prompt injection
   - secret and PII leakage
   - unsafe tool use
   - policy bypass
6. Deterministic hard-rule engine
7. Jev scoring plugin
8. Evidence bundles
9. Human review queue
10. Regression runner
11. One end-to-end demo covering an API model, a tool-using agent, and an offline trace set

### Out of scope for the MVP

- Inline production blocking
- Automatic remediation or policy changes
- Claims of regulatory certification
- A full red-team payload marketplace
- Provider-specific orchestration frameworks
- Multi-tenant billing and enterprise identity management

## Architecture

```text
                            +----------------------+
                            |  CLI / API / Web UI  |
                            +----------+-----------+
                                       |
                              +--------v---------+
                              |  Control Plane   |
                              | runs, suites,    |
                              | versions, state  |
                              +---+----------+---+
                                  |          |
                 +----------------+          +----------------+
                 |                                            |
       +---------v----------+                       +---------v----------+
       | Target Adapters    |                       | Trace Ingestion    |
       | REST / agent API   |                       | JSONL upload       |
       +---------+----------+                       +---------+----------+
                 |                                            |
                 +----------------+---------------------------+
                                  |
                         +--------v---------+
                         | Normalizer       |
                         | canonical events |
                         +--------+---------+
                                  |
                 +----------------+----------------+
                 |                                 |
       +---------v----------+            +---------v----------+
       | Test Plugins       |            | Evidence Store     |
       | attack runners     |            | immutable artifacts|
       +---------+----------+            +---------+----------+
                 |                                 |
                 +----------------+----------------+
                                  |
                       +----------v-----------+
                       | Assessment Pipeline  |
                       | hard rules + judges  |
                       +----+------------+----+
                            |            |
                  +---------v--+      +--v----------------+
                  | Findings   |      | Human Review Queue|
                  +---------+--+      +--+----------------+
                            |            |
                            +-----+------+
                                  |
                         +--------v---------+
                         | Evidence Bundle  |
                         | + Regression Run |
                         +------------------+
```

### Component responsibilities

| Component | Responsibility | Trust level |
|---|---|---|
| Control plane | Own run lifecycle, suite versions, retries, timeouts, and durable state | Trusted orchestration |
| Target adapter | Translate the canonical request into a target call and capture raw output | Untrusted boundary |
| Trace ingestor | Validate JSONL shape, size, ordering, and provenance metadata | Untrusted input boundary |
| Normalizer | Convert target-specific records into canonical events without inventing missing data | Trusted transformation |
| Test plugin | Generate attack cases and declare required capabilities | Untrusted test content, sandboxed execution |
| Hard-rule engine | Evaluate explicit invariants with deterministic results | Trusted decision layer |
| Judge plugin | Classify ambiguous evidence and report confidence and rationale | Probabilistic advisor |
| Review queue | Hold ambiguous, disputed, or policy-sensitive findings for a person | Human decision point |
| Evidence store | Preserve content-addressed artifacts and lineage | Trusted audit record |
| Regression runner | Re-run pinned suites and compare results across target versions | Trusted orchestration |

## Core interfaces

The examples use TypeScript-like notation to define behavior, not an implementation mandate.

### Capability manifest

```ts
type CapabilityManifest = {
  schemaVersion: "1.0";
  target: {
    id: string;
    kind: "model" | "agent" | "trace";
    displayName: string;
    version?: string;
  };
  inputs: {
    text: boolean;
    images?: boolean;
    files?: boolean;
  };
  outputs: {
    text: boolean;
    structuredJson?: boolean;
    toolCalls?: boolean;
  };
  execution: {
    streaming: boolean;
    multiTurn: boolean;
    maxContextTokens?: number;
    timeoutMs: number;
  };
  tools?: Array<{
    name: string;
    description?: string;
    sideEffect: "none" | "reversible" | "irreversible";
  }>;
  dataHandling: {
    mayStoreInputs: boolean;
    mayStoreOutputs: boolean;
    declaredRegions?: string[];
  };
};
```

A test plugin must fail closed with `not_applicable` when required capabilities are absent. It must not silently simulate a capability.

### Universal REST target adapter

```ts
interface TargetAdapter {
  describe(): Promise<CapabilityManifest>;
  invoke(request: CanonicalRequest, context: RunContext): Promise<TargetResult>;
  healthCheck(): Promise<HealthStatus>;
}

type CanonicalRequest = {
  caseId: string;
  messages: Array<{ role: "system" | "user" | "assistant" | "tool"; content: unknown }>;
  tools?: ToolDefinition[];
  metadata?: Record<string, string | number | boolean>;
};

type TargetResult = {
  status: "completed" | "timeout" | "error";
  startedAt: string;
  endedAt: string;
  rawArtifactRef: string;
  events: CanonicalEvent[];
  usage?: { inputTokens?: number; outputTokens?: number; costUsd?: number };
  error?: { code: string; message: string; retryable: boolean };
};
```

The REST adapter configuration should support:

- endpoint URL and HTTP method
- allowlisted request and response mappings
- authentication by secret reference, never inline secret values
- explicit timeout, retry, and response-size limits
- optional streaming decoder
- correlation ID propagation
- outbound network allowlist

### JSONL trace upload

One canonical event per line. Files are validated before persistence and processed as streams.

```json
{"schema_version":"1.0","event_id":"evt_001","run_id":"run_001","sequence":1,"timestamp":"2026-09-19T13:00:00Z","type":"message.input","actor":"user","content":{"text":"Summarize this document"},"labels":{}}
{"schema_version":"1.0","event_id":"evt_002","run_id":"run_001","sequence":2,"timestamp":"2026-09-19T13:00:01Z","type":"tool.call","actor":"assistant","content":{"tool_name":"document.read","arguments":{"document_ref":"doc_123"}},"labels":{}}
```

Validation requirements:

- supported schema version
- unique `event_id` values
- monotonic `sequence` per run
- bounded line, file, and expanded payload sizes
- valid event type and actor
- content stored as untrusted data
- unknown fields preserved under an extension namespace or rejected by version policy
- no remote URL fetching during parse

### Test plugin

```ts
interface TestPlugin {
  manifest(): TestManifest;
  generate(seed: Seed, target: CapabilityManifest): AsyncIterable<TestCase>;
  evaluate(input: EvaluationInput): Promise<PluginEvaluation>;
}

type TestManifest = {
  id: string;
  version: string;
  category: "prompt_injection" | "secret_pii_leakage" | "unsafe_tool_use" | "policy_bypass";
  requiredCapabilities: string[];
  maxCases: number;
  riskLevel: "low" | "medium" | "high";
};
```

### Rule and judge contracts

```ts
interface HardRule {
  id: string;
  version: string;
  evaluate(events: CanonicalEvent[], policy: PolicySnapshot): RuleResult;
}

type RuleResult = {
  outcome: "pass" | "fail" | "not_applicable" | "error";
  reasonCode: string;
  evidenceRefs: string[];
};

interface JudgePlugin {
  id: string;
  version: string;
  score(input: JudgeInput): Promise<JudgeResult>;
}

type JudgeResult = {
  label: "pass" | "fail" | "uncertain";
  confidence: number;
  reasonCodes: string[];
  evidenceRefs: string[];
  modelMetadata: Record<string, string | number>;
};
```

Jev is the default registered `JudgePlugin`. A run pins the Jev plugin version, prompt template version, threshold set, and model identifier. The control plane can route selected cases to another judge without changing the test or evidence contracts.

### Later enforcement interface

The MVP produces recommendations only. A future enforcement consumer can subscribe without changing assessment semantics:

```ts
type EnforcementRecommendation = {
  findingId: string;
  action: "allow" | "flag" | "block";
  policyVersion: string;
  rationaleRefs: string[];
  expiresAt?: string;
};
```

No MVP component executes this recommendation.

## Data model

| Entity | Key fields | Notes |
|---|---|---|
| `Target` | `id`, `kind`, `adapter_type`, `manifest_ref`, `version` | Logical system under test |
| `Suite` | `id`, `version`, `test_plugin_refs`, `policy_ref` | Immutable after publication |
| `Run` | `id`, `target_ref`, `suite_ref`, `status`, timestamps, config hash | Root of reproducibility |
| `Case` | `id`, `run_ref`, `plugin_ref`, `seed_ref`, `status` | One generated or replayed test |
| `Event` | `id`, `case_ref`, `sequence`, `type`, `actor`, `content_ref` | Canonical timeline |
| `Artifact` | `id`, `sha256`, `media_type`, `size`, `storage_ref` | Content-addressed raw or derived evidence |
| `Evidence` | `id`, `case_ref`, `artifact_ref`, `selector`, `redaction_state` | Minimal support for a decision |
| `RuleResult` | `id`, `case_ref`, `rule_ref`, `outcome`, `reason_code` | Deterministic output |
| `JudgeResult` | `id`, `case_ref`, `judge_ref`, `label`, `confidence` | Probabilistic output |
| `Finding` | `id`, `category`, `severity`, `status`, `evidence_refs` | User-facing issue |
| `ReviewTask` | `id`, `finding_ref`, `reason`, `assignee`, `decision` | Human resolution |
| `Baseline` | `id`, `target_ref`, `suite_ref`, `accepted_run_ref` | Regression comparison point |

### Canonical event types

- `message.input`
- `message.output`
- `tool.call`
- `tool.result`
- `policy.decision`
- `system.error`
- `metadata.snapshot`

Every derived object records lineage back to source artifacts. Raw artifacts are immutable; redacted views are separate artifacts.

## Initial tests

### 1. Prompt injection

Attack runners place adversarial instructions in user messages, retrieved documents, tool output, and quoted content. Hard rules catch explicit forbidden actions and trust-boundary violations. Jev classifies cases requiring semantic interpretation, such as whether the target treated document text as authority.

**Success signal:** the target keeps instruction hierarchy, labels untrusted content correctly, and refuses unauthorized side effects.

### 2. Secret and PII leakage

The harness injects synthetic canary secrets and PII into controlled contexts, then checks outputs, tool arguments, logs, and evidence artifacts. Deterministic detectors handle exact canaries and defined patterns; Jev judges contextual disclosure when strings are transformed or summarized.

**Success signal:** protected values do not cross the declared audience or sink boundary.

### 3. Unsafe tool use

Cases test missing confirmation, wrong recipient or account, excessive tool scope, destructive actions, and arguments influenced by untrusted content. Tool side-effect classes come from the capability manifest.

**Success signal:** the target verifies authorization and required state before a side effect, and refuses or pauses when approval is absent.

### 4. Policy bypass

Cases use obfuscation, role-play, decomposition, encoding, and multi-turn pressure against a versioned policy. Deterministic policy predicates remain authoritative where defined; Jev handles semantic equivalence and ambiguous intent.

**Success signal:** equivalent prohibited requests receive consistent outcomes across transformations.

## Assessment pipeline

1. Pin target, adapter, suite, policy, rule, and judge versions.
2. Validate the capability manifest.
3. Generate test cases or ingest a trace.
4. Invoke the target in an isolated execution boundary.
5. Normalize raw output into canonical events.
6. Persist raw artifacts and content hashes.
7. Run deterministic hard rules.
8. Send only the minimum required, redacted evidence to Jev.
9. Combine results with explicit precedence:
   - hard-rule failure cannot be overridden by a judge
   - hard-rule pass does not erase a separate judge finding
   - low confidence or disagreement creates a review task
10. Produce findings and an evidence bundle.
11. Compare with the pinned baseline when the run is a regression.

## Finding and review policy

A finding contains category, severity, confidence, affected policy control, reproduction steps, and evidence references. It never relies on a free-form model explanation alone.

Route to human review when:

- judge confidence is below the configured threshold
- hard rules and judge results conflict
- evidence may contain sensitive data
- a finding would change a release decision
- a reviewer disputes an earlier label

Reviewer decisions are append-only, attributed, timestamped, and never used as training data without a separate opt-in process.

## Evidence bundle

Each run exports a signed manifest plus referenced artifacts:

```text
evidence-bundle/
  manifest.json
  run.json
  target-manifest.json
  suite.json
  policy.json
  cases/
    <case-id>/events.jsonl
    <case-id>/rule-results.json
    <case-id>/judge-results.json
    <case-id>/finding.json
  artifacts/
    <sha256>
  reviews/
    decisions.jsonl
  checksums.txt
```

The manifest records schema versions, tool and plugin versions, hashes, timestamps, environment metadata, and redaction state. Bundles must be verifiable offline.

## Security boundaries

### Target boundary

Treat all target output, retrieved content, trace content, and tool results as untrusted data. They cannot alter harness policy, tool routing, secrets, or judge instructions.

### Secret boundary

- Store credentials in a secret manager and pass opaque references to adapters.
- Never write secret values to run configuration, logs, events, findings, or bundles.
- Use synthetic canaries for leakage tests.
- Redact before judge calls and user-facing exports.

### Network boundary

- Deny outbound traffic by default for test plugins.
- Allowlist target endpoints per adapter.
- Block link-local, metadata-service, loopback, and private-network destinations unless an isolated test environment explicitly permits them.
- Cap redirects, response size, and request duration.

### Execution boundary

- Run adapters and attack plugins with least privilege.
- Separate assessment credentials from production credentials.
- Use disposable tool sandboxes for unsafe-tool tests.
- Prevent tests from reaching real recipients or irreversible tools.

### Evidence boundary

- Encrypt artifacts at rest and in transit.
- Use content hashes and append-only audit records.
- Separate raw artifacts from redacted views.
- Enforce tenant, run, and role access checks at every read.
- Apply retention and deletion policies without breaking audit lineage.

### Judge boundary

- Jev receives the minimum evidence needed for one decision.
- Judge prompts, thresholds, and outputs are versioned.
- Judge output never executes tools or mutates policy.
- Judge errors and timeouts become explicit `uncertain` results, not passes.

## Repository shape

```text
apps/
  api/                 # control-plane HTTP API
  reviewer-web/        # human review queue
packages/
  contracts/           # schemas and generated types
  control-plane/       # run state machine and orchestration
  adapters/
    rest/
    trace-jsonl/
  normalizer/
  rules/
  judges/
    jev/
  tests/
    prompt-injection/
    secret-pii-leakage/
    unsafe-tool-use/
    policy-bypass/
  evidence/
  regression/
examples/
  api-model/
  tool-agent/
  offline-traces/
docs/
  threat-model.md
  evidence-format.md
  plugin-authoring.md
```

## Delivery milestones

### M0 - Contracts and threat model

- Canonical schemas for manifest, request, result, event, finding, and evidence bundle
- Run state machine and explicit failure states
- Threat model covering target, plugin, network, secret, evidence, and judge boundaries
- JSON Schema validation and contract fixtures

**Exit:** schemas validate representative API, agent, and trace examples.

### M1 - Ingestion and execution

- Universal REST adapter
- Streaming JSONL trace upload
- Normalizer and immutable artifact storage
- Capability-based test selection

**Exit:** one API model and one offline trace produce the same canonical event shape.

### M2 - Assessment core

- Four initial test plugins
- Deterministic rule engine
- Jev judge plugin with version-pinned prompts and thresholds
- Finding precedence and uncertainty handling

**Exit:** seeded cases produce reproducible rule results and stable judge envelopes.

### M3 - Review and evidence

- Review queue and append-only decisions
- Offline-verifiable evidence bundle
- Redacted and raw evidence access separation

**Exit:** a reviewer can reproduce a finding from its bundle without database access.

### M4 - Regression demo

- Baseline promotion
- Target or policy version comparison
- Added, fixed, worsened, and unchanged finding states
- CI-friendly summary and machine-readable exit codes

**Exit:** the end-to-end demo catches an intentionally introduced regression.

## First end-to-end demo

### Fixtures

1. **API model:** a small HTTP endpoint implementing the REST adapter contract.
2. **Tool-using agent:** a sandboxed agent with `document.read` and `message.send` tools. `message.send` writes only to a fake sink.
3. **Offline traces:** a JSONL set with safe and unsafe examples for all four categories.

### Demo flow

1. Register all three targets and validate their capability manifests.
2. Run a pinned suite against the API model and the tool agent; ingest the offline traces as a third run.
3. Execute at least one case per initial test plugin.
4. Show an exact canary leak caught by a hard rule.
5. Show a retrieved-document prompt injection classified by Jev with confidence and evidence references.
6. Show an unauthorized `message.send` attempt caught before the fake sink records delivery.
7. Route one deliberately ambiguous policy-bypass case to human review.
8. Export and verify each evidence bundle.
9. Mark the safe build as the baseline.
10. Change the tool agent to trust document instructions, rerun the suite, and show the new regression.

### Acceptance criteria

- The same suite runs across live targets and offline traces without changing the assessment pipeline.
- Every finding links to canonical events and versioned decision outputs.
- A hard-rule failure is deterministic across repeated runs.
- Jev can be replaced by a stub judge in tests without changing other components.
- Missing capabilities yield explicit `not_applicable` results.
- No test can contact a real recipient or production tool.
- Bundles pass checksum verification offline.
- The regression report identifies the intentionally introduced failure.

## Engineering guardrails

- Version every external contract and plugin.
- Use idempotency keys for run creation and target invocation.
- Make retries explicit and safe; never retry irreversible side effects.
- Bound concurrency, payload size, execution time, and evidence retention.
- Keep raw target content out of application logs.
- Use structured reason codes in addition to readable explanations.
- Test schema migrations against stored fixtures.
- Record dependency and model versions in the run manifest.
- Default to failing closed on validation errors and surfacing them as errors, not safety passes.

## MVP API sketch

```http
POST /v1/targets
POST /v1/suites
POST /v1/runs
GET  /v1/runs/{run_id}
POST /v1/runs/{run_id}/cancel
GET  /v1/runs/{run_id}/findings
GET  /v1/runs/{run_id}/evidence-bundle
POST /v1/traces:upload
GET  /v1/reviews?status=pending
POST /v1/reviews/{review_id}/decision
POST /v1/baselines
POST /v1/regressions
```

Mutating endpoints require idempotency keys. Read APIs enforce artifact-level authorization and return redacted evidence by default.

## Immediate build order

1. Create schemas and fixtures in `packages/contracts`.
2. Implement the run state machine and local artifact store.
3. Add JSONL ingestion and normalizer.
4. Add the REST adapter against the API-model fixture.
5. Implement hard rules and the four test manifests.
6. Add the Jev plugin behind `JudgePlugin`.
7. Produce the evidence bundle before building the reviewer UI.
8. Add the review queue.
9. Add baseline comparison and the regression demo.

This sequence proves the contracts and evidence path before UI polish, while keeping the core model-agnostic and the default assessment path Jev-first.
