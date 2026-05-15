import type { Decision, Event, EventBuckets, EventGroups, Session } from "./types";

const DETERMINISTIC_REASON_CODES = new Set([
  "production_mutation",
  "credential_access_without_intent",
  "destructive_operation_without_intent",
  "direct_infra_api_with_credential",
  "unknown_high_risk_command",
]);

export function bucket(events: Event[]): EventBuckets {
  const groups: EventGroups = { deny: [], ask: [], allow: [] };
  for (const e of events) groups[e.decision]?.push(e);
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
    if (a[i].session_id !== b[i].session_id || a[i].actions !== b[i].actions) return false;
  }
  return true;
}

export function prettyTool(t?: string): string {
  if (!t) return "tool";
  return humanize(t).replace(/\b\w/g, (c) => c.toUpperCase());
}

export function isDeterministicGuard(e: Event): boolean {
  return Boolean(e.risk_event?.guard_id) || DETERMINISTIC_REASON_CODES.has(e.reason_code ?? "");
}

export function humanReason(e: Event): string {
  if (e.reason_code === "async_telemetry") return "Recorded after execution.";
  if (e.reason_code === "model_risk_threshold") {
    return "Markov sequence risk crossed the local threshold.";
  }
  return e.reason || e.reason_code || "No explanation captured.";
}

export function technicalExplanation(e: Event): string {
  const r = e.risk_event ?? {};
  const score = scoreLabel(e);
  const threshold = thresholdLabel(e);
  if (e.reason_code === "model_risk_threshold") {
    return `The Markov-chain model scored this normalized action at ${score}, at or above threshold ${threshold}.`;
  }
  if (e.reason_code === "async_telemetry") {
    return "Not a live gate. Recorded after execution to improve future model parameters.";
  }
  if (isDeterministicGuard(e)) {
    return `A deterministic rule fired before the model decision mattered. Markov score is ${score} against threshold ${threshold}.`;
  }
  if (r.type === "normal_tool_call") {
    return `Model score is ${score} against threshold ${threshold}. Routine coding-agent behavior.`;
  }
  return `Normalized as ${r.type || "unknown"} with model score ${score} against threshold ${threshold}.`;
}

export function decisionSource(e: Event): string {
  if (e.reason_code === "model_risk_threshold") return "Markov-chain model";
  if (e.reason_code === "async_telemetry") return "Trace history";
  if (isDeterministicGuard(e)) return "Deterministic rule";
  return "Normal scoring";
}

export function actionSummary(e: Event): string {
  return summaryOf(e, "No command summary stored.");
}

export function scoreLabel(e: Event): string {
  return e.risk_score == null ? "n/a" : e.risk_score.toFixed(3);
}

export function thresholdLabel(e: Event): string {
  return e.threshold == null ? "n/a" : e.threshold.toFixed(3);
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

export function decisionLabel(decision: Event["decision"]): string {
  if (decision === "deny") return "Would deny";
  if (decision === "ask") return "Would ask";
  return "Allow";
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
    text: "text-amber-700",
    bg: "bg-amber-500",
    ring: "ring-amber-500/10",
    border: "border-amber-300/40",
  },
  allow: {
    text: "text-brand",
    bg: "bg-brand",
    ring: "ring-brand/10",
    border: "border-border",
  },
};
