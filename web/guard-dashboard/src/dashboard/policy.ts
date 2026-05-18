import type { PolicyProfileDef, PolicyProfileID } from "./types";

export const POLICY_PROFILES: PolicyProfileDef[] = [
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
];

export function profileLabel(id: PolicyProfileID): string {
  return POLICY_PROFILES.find((p) => p.id === id)?.label ?? "Balanced";
}
