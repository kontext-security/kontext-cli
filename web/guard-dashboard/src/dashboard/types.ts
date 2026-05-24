export const DECISIONS = ["deny", "allow"] as const;
export type Decision = (typeof DECISIONS)[number];

export const GUARD_MODES = ["observe", "enforce"] as const;
export type GuardMode = (typeof GUARD_MODES)[number];

export type Tab = "all" | "deny" | "allow";

export type LogView = "decisions" | "observed";

export const POLICY_PROFILE_IDS = ["relaxed", "balanced", "strict"] as const;
export type PolicyProfileID = (typeof POLICY_PROFILE_IDS)[number];

export function isDecision(value: unknown): value is Decision {
  return typeof value === "string" && (DECISIONS as readonly string[]).includes(value);
}

export function isGuardMode(value: unknown): value is GuardMode {
  return typeof value === "string" && (GUARD_MODES as readonly string[]).includes(value);
}

export function isPolicyProfileID(value: unknown): value is PolicyProfileID {
  return typeof value === "string" && (POLICY_PROFILE_IDS as readonly string[]).includes(value);
}

export type RiskEvent = {
  type?: string;
  provider?: string;
  provider_category?: string;
  operation?: string;
  operation_class?: string;
  resource_class?: string;
  environment?: string;
  credential_observed?: boolean;
  credential_source?: string;
  direct_api_call?: boolean;
  explicit_user_intent?: boolean;
  command_summary?: string;
  request_summary?: string;
  path_class?: string;
  decision?: Decision;
  reason_code?: string;
  decision_stage?: string;
  signals?: string[];
  guard_id?: string;
  confidence?: number;
  policy_version?: string;
  policy_profile?: string;
  policy_rule_pack?: string;
  policy_rule_id?: string;
  policy_rule_category?: string;
  policy_signals?: string[];
  judge_runtime?: string;
  judge_model?: string;
  judge_duration_ms?: number;
  judge_failure_kind?: string;
  judge_risk_level?: string;
  judge_categories?: string[];
};

export type Event = {
  id: string;
  session_id?: string;
  tool_name?: string;
  decision: Decision;
  reason?: string;
  reason_code?: string;
  created_at?: string;
  risk_event?: RiskEvent;
};

export type ObservedActivityEvent = Event &
  (
    | { reason_code: "async_telemetry" }
    | { risk_event: RiskEvent & { decision_stage: "async_telemetry" } }
  );

export type Session = {
  session_id: string;
  actions: number;
  current?: boolean;
  mode?: GuardMode;
};

export type PolicyProfile = {
  profile: PolicyProfileID;
  recommended_profile?: PolicyProfileID;
  version?: string;
  rule_pack?: string;
  rule_pack_version?: string;
  config_digest?: string;
  activation_id?: string;
  source?: string;
  status?: string;
  loaded_at?: string;
};

export type PolicyProfileDef = {
  id: PolicyProfileID;
  label: string;
  lede: string;
  hint: string;
  recommended?: boolean;
};

export type Counts = {
  all: number;
  deny: number;
  allow: number;
};

export type EventGroups = Record<Decision, Event[]>;

export type EventPartitions = {
  decisionEvents: Event[];
  observedActivityEvents: ObservedActivityEvent[];
};

export type EventBuckets = {
  counts: Counts;
  groups: EventGroups;
};
