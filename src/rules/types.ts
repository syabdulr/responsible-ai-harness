import type { CanonicalEvent, PolicySnapshot, RuleResult } from "../contracts/types.ts";

export interface HardRule {
  id: string;
  version: string;
  requiredCapability: string;
  evaluate(events: CanonicalEvent[], policy: PolicySnapshot, caseId: string): RuleResult;
}
