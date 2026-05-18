import { API } from "./config";
import type { Decision, Event, PolicyProfile, PolicyProfileID, RiskEvent, Session } from "./types";

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function responseJSON(r: Response): Promise<unknown> {
  return r.json();
}

async function ok(r: Response): Promise<unknown> {
  if (r.ok) return responseJSON(r);
  const fallback = `${r.status} ${r.statusText}`.trim();
  const contentType = r.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    throw new Error(fallback);
  }

  let body: unknown;
  try {
    body = await responseJSON(r);
  } catch (error) {
    throw new Error(`API error response was not valid JSON: ${fallback}; ${errorMessage(error)}`);
  }

  const reason = isObject(body) && typeof body.error === "string" ? body.error : fallback;
  throw new Error(reason);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function optionalBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function optionalNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function nullableNumber(value: unknown): number | null | undefined {
  if (value === null) return null;
  return optionalNumber(value);
}

function stringList(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const strings = value.filter((item): item is string => typeof item === "string");
  return strings.length > 0 ? strings : undefined;
}

function decision(value: unknown): Decision | undefined {
  switch (value) {
    case "allow":
    case "ask":
    case "deny":
      return value;
    default:
      return undefined;
  }
}

function policyProfileID(value: unknown): PolicyProfileID | undefined {
  switch (value) {
    case "relaxed":
    case "balanced":
    case "strict":
      return value;
    default:
      return undefined;
  }
}

function parseRiskEvent(value: unknown): RiskEvent | undefined {
  if (!isObject(value)) return undefined;
  return {
    type: optionalString(value.type),
    provider: optionalString(value.provider),
    provider_category: optionalString(value.provider_category),
    operation: optionalString(value.operation),
    operation_class: optionalString(value.operation_class),
    resource_class: optionalString(value.resource_class),
    environment: optionalString(value.environment),
    credential_observed: optionalBoolean(value.credential_observed),
    credential_source: optionalString(value.credential_source),
    direct_api_call: optionalBoolean(value.direct_api_call),
    explicit_user_intent: optionalBoolean(value.explicit_user_intent),
    command_summary: optionalString(value.command_summary),
    request_summary: optionalString(value.request_summary),
    path_class: optionalString(value.path_class),
    decision: decision(value.decision),
    reason_code: optionalString(value.reason_code),
    model_version: optionalString(value.model_version),
    signals: stringList(value.signals),
    guard_id: optionalString(value.guard_id),
    risk_score: nullableNumber(value.risk_score),
    confidence: optionalNumber(value.confidence),
  };
}

function parseSession(value: unknown): Session | undefined {
  if (
    !isObject(value) ||
    typeof value.session_id !== "string" ||
    typeof value.actions !== "number"
  ) {
    return undefined;
  }
  return {
    session_id: value.session_id,
    actions: value.actions,
  };
}

function parseEvent(value: unknown): Event | undefined {
  if (!isObject(value) || typeof value.id !== "string") return undefined;
  const parsedDecision = decision(value.decision);
  if (!parsedDecision) return undefined;
  return {
    id: value.id,
    session_id: optionalString(value.session_id),
    tool_name: optionalString(value.tool_name),
    decision: parsedDecision,
    reason: optionalString(value.reason),
    reason_code: optionalString(value.reason_code),
    risk_score: nullableNumber(value.risk_score),
    threshold: nullableNumber(value.threshold),
    risk_event: parseRiskEvent(value.risk_event),
  };
}

function parsePolicyProfile(value: unknown): PolicyProfile {
  if (!isObject(value)) throw new Error("invalid policy profile response");
  const profile = policyProfileID(value.profile);
  if (!profile) throw new Error("invalid policy profile response");
  return {
    profile,
    recommended_profile: policyProfileID(value.recommended_profile),
    version: optionalString(value.version),
    rule_pack: optionalString(value.rule_pack),
    rule_pack_version: optionalString(value.rule_pack_version),
    config_digest: optionalString(value.config_digest),
    activation_id: optionalString(value.activation_id),
    source: optionalString(value.source),
    status: optionalString(value.status),
    loaded_at: optionalString(value.loaded_at),
  };
}

function parseList<T>(value: unknown, parse: (item: unknown) => T | undefined): T[] {
  if (value == null) return [];
  if (!Array.isArray(value)) throw new Error("invalid API response");
  const items: T[] = [];
  for (const item of value) {
    const parsed = parse(item);
    if (!parsed) throw new Error("invalid API response");
    items.push(parsed);
  }
  return items;
}

export async function fetchSessions(): Promise<Session[]> {
  return parseList(await fetch(`${API}/api/sessions`).then(ok), parseSession);
}

export async function fetchEvents(sessionID: string): Promise<Event[]> {
  return parseList(
    await fetch(`${API}/api/sessions/${encodeURIComponent(sessionID)}/events`).then(ok),
    parseEvent,
  );
}

export async function fetchPolicy(): Promise<PolicyProfile> {
  return parsePolicyProfile(await fetch(`${API}/api/policy/profile`).then(ok));
}

export async function activatePolicy(profile: PolicyProfileID): Promise<PolicyProfile> {
  const response = await fetch(`${API}/api/policy/profile`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ profile }),
  }).then(ok);
  return parsePolicyProfile(response);
}
