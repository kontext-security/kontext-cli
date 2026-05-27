export const POLICY_PROFILES = [
  {
    id: "relaxed",
    label: "Relaxed",
    lede: "Fewer blocks, more compatibility.",
    hint: "Use when iterating on agent behavior.",
  },
  {
    id: "balanced",
    label: "Balanced",
    recommended: true,
    lede: "Good protection with fewer false positives.",
    hint: "Best default for local development.",
  },
  {
    id: "strict",
    label: "Strict",
    lede: "Maximum protection, more false positives.",
    hint: "Use when you can accept breakage.",
  },
] as const;

export type PolicyProfileID = (typeof POLICY_PROFILES)[number]["id"];

export type PolicyProfileDef = {
  id: PolicyProfileID;
  label: string;
  lede: string;
  hint: string;
  recommended?: boolean;
};

export function isPolicyProfileID(value: unknown): value is PolicyProfileID {
  return typeof value === "string" && POLICY_PROFILES.some((p) => p.id === value);
}

export function profileLabel(id: PolicyProfileID): string {
  return POLICY_PROFILES.find((p) => p.id === id)?.label ?? "Balanced";
}

