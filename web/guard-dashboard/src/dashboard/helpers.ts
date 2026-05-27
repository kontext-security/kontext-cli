import type {
  Decision,
  Event,
  EventBuckets,
  EventGroups,
  GuardMode,
  Session,
} from "./types";

const DETERMINISTIC_REASON_CODES = new Set([
  "production_mutation",
  "credential_access_without_intent",
  "destructive_operation_without_intent",
  "direct_infra_api_with_credential",
  "unknown_high_risk_command",
  "no_policy_rule_matched",
]);

const JUDGE_STAGES = new Set(["judge_allow", "judge_deny", "judge_fail_open"]);
const DETERMINISTIC_STAGES = new Set(["deterministic_deny", "deterministic_allow"]);

export function bucket(events: Event[]): EventBuckets {
  const groups: EventGroups = { deny: [], ask: [], allow: [] };
  for (const e of events) groups[e.decision].push(e);
  return {
    counts: {
      all: events.length,
      deny: groups.deny.length,
      ask: groups.ask.length,
      allow: groups.allow.length,
    },
    groups,
  };
}

export function summaryOf(e: Event, fallback = "—"): string {
  const r = e.risk_event ?? {};
  return r.command_summary || r.request_summary || r.path_class || r.type || fallback;
}

export function humanize(s: string): string {
  return s.replace(/_/g, " ");
}

export function sameSessions(a: Session[], b: Session[]): boolean {
  if (a === b) return true;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (
      a[i].session_id !== b[i].session_id ||
      a[i].actions !== b[i].actions ||
      a[i].latest_at !== b[i].latest_at ||
      a[i].status !== b[i].status ||
      a[i].created_at !== b[i].created_at ||
      a[i].updated_at !== b[i].updated_at ||
      a[i].closed_at !== b[i].closed_at ||
      a[i].current !== b[i].current ||
      a[i].mode !== b[i].mode
    ) {
      return false;
    }
  }
  return true;
}

export function prettyTool(t?: string): string {
  if (!t) return "tool";
  return humanize(t).replace(/\b\w/g, (c) => c.toUpperCase());
}

export function isDeterministicGuard(e: Event): boolean {
  const stage = e.risk_event?.decision_stage;
  return (
    Boolean(stage && DETERMINISTIC_STAGES.has(stage)) ||
    DETERMINISTIC_REASON_CODES.has(e.reason_code ?? "")
  );
}

export function humanReason(e: Event): string {
  if (e.risk_event?.decision_stage === "judge_fail_open") {
    return "Local judge was unavailable, so Guard allowed by fail-open policy.";
  }
  return e.reason || (e.reason_code ? humanize(e.reason_code) : "No explanation captured.");
}

export function technicalExplanation(e: Event): string {
  const r = e.risk_event ?? {};
  if (r.decision_stage === "judge_allow") {
    return "Deterministic policy allowed this action, then the local judge allowed it.";
  }
  if (r.decision_stage === "judge_deny") {
    return "Deterministic policy allowed this action, then the local judge denied it.";
  }
  if (r.decision_stage === "judge_fail_open") {
    return `Deterministic policy allowed this action, but the local judge failed${r.judge_failure_kind ? ` with ${humanize(r.judge_failure_kind)}` : ""}.`;
  }
  if (isDeterministicGuard(e)) {
    return r.policy_rule_id
      ? `Deterministic policy matched ${r.policy_rule_id} before calling the local judge.`
      : "Deterministic policy allowed this action.";
  }
  if (r.type === "normal_tool_call") {
    return "Routine coding-agent behavior. No deterministic policy rule matched.";
  }
  return `Normalized as ${r.type || "unknown"}.`;
}

export function decisionSource(e: Event): string {
  const stage = e.risk_event?.decision_stage;
  if (stage && JUDGE_STAGES.has(stage)) return "Local LLM judge";
  if (isDeterministicGuard(e)) return "Deterministic policy";
  return "Guard policy";
}

export function actionSummary(e: Event): string {
  return summaryOf(e, "No command summary stored.");
}

export function relativeTime(value?: string): string {
  if (!value) return "just now";
  const ts = Date.parse(value);
  if (Number.isNaN(ts)) return "just now";
  const s = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (s < 60) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export function dateTime(value?: string): string {
  if (!value) return "";
  const ts = Date.parse(value);
  if (Number.isNaN(ts)) return "";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(ts);
}

export function decisionLabel(decision: Decision, mode: GuardMode): string {
  if (decision === "ask") {
    return mode === "enforce" ? "Needs approval" : "Would require approval";
  }
  if (mode === "enforce") {
    return decision === "deny" ? "Denied" : "Allowed";
  }
  return decision === "deny" ? "Would deny" : "Would allow";
}

export const decisionTone: Record<
  Decision,
  { text: string; bg: string; ring: string; border: string }
> = {
  deny: {
    text: "text-destructive",
    bg: "bg-destructive",
    ring: "ring-destructive/10",
    border: "border-destructive/20",
  },
  ask: {
    text: "text-amber-600",
    bg: "bg-amber-500",
    ring: "ring-amber-500/10",
    border: "border-amber-500/25",
  },
  allow: {
    text: "text-brand",
    bg: "bg-brand",
    ring: "ring-brand/10",
    border: "border-border",
  },
};
