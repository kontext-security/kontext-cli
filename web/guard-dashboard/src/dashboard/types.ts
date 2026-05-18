export type Decision = "allow" | "ask" | "deny";

export type Tab = "all" | "deny" | "ask" | "allow";

export type PolicyProfileID = "relaxed" | "balanced" | "strict";

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
  model_version?: string;
  signals?: string[];
  guard_id?: string;
  risk_score?: number | null;
  confidence?: number;
};

export type Event = {
  id: string;
  session_id?: string;
  tool_name?: string;
  decision: Decision;
  reason?: string;
  reason_code?: string;
  risk_score?: number | null;
  threshold?: number | null;
  risk_event?: RiskEvent;
};

export type Session = {
  session_id: string;
  actions: number;
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
  ask: number;
  deny: number;
  allow: number;
};

export type EventGroups = Record<Decision, Event[]>;

export type EventBuckets = {
  counts: Counts;
  groups: EventGroups;
};
