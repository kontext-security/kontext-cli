import { AlertCircle, Info, Loader2 } from "lucide-react";
import { HoverCard, HoverCardContent, HoverCardTrigger } from "@/components/ui/hover-card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { POLICY_PROFILES, profileLabel } from "./policy";
import { Kv } from "./shared";
import type { PolicyProfile, PolicyProfileDef, PolicyProfileID } from "./types";

const STEP_DOTS: Record<PolicyProfileID, number> = { relaxed: 1, balanced: 2, strict: 3 };

export function PolicyPanel({
  profile,
  pending,
  error,
  onActivate,
  onRetry,
}: {
  profile: PolicyProfile | null;
  pending: PolicyProfileID | null;
  error: string;
  onActivate: (id: PolicyProfileID) => void;
  onRetry: () => void;
}) {
  const active = profile?.profile ?? "balanced";
  const isLoading = !profile && !error;

  return (
    <section className="space-y-3.5">
      <div className="flex items-baseline justify-between gap-3">
        <div className="flex items-baseline gap-3">
          <h2 className="text-[15px] font-semibold tracking-tight">Policy profile</h2>
          {profile && (
            <span className="font-mono text-[11px] text-muted-foreground">
              {profileLabel(profile.profile)} profile
            </span>
          )}
        </div>
        {profile && <PolicyVersionChip profile={profile} />}
      </div>

      <div className="grid grid-cols-1 gap-2.5 md:grid-cols-3">
        {isLoading
          ? POLICY_PROFILES.map((p) => <PolicyCardSkeleton key={p.id} />)
          : POLICY_PROFILES.map((p) => (
              <PolicyCard
                key={p.id}
                profile={p}
                active={p.id === active}
                pending={p.id === pending}
                disabled={!profile || !!pending}
                onActivate={() => onActivate(p.id)}
              />
            ))}
      </div>

      {error && (
        <div className="flex items-center justify-between gap-3 rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-[12px] text-destructive">
          <span className="flex min-w-0 items-center gap-2">
            <AlertCircle className="h-3.5 w-3.5 shrink-0" />
            <span>{error}</span>
          </span>
          <button
            type="button"
            onClick={onRetry}
            className="shrink-0 font-mono text-[10.5px] uppercase tracking-[0.18em] text-destructive underline-offset-4 hover:underline"
          >
            Retry
          </button>
        </div>
      )}
    </section>
  );
}

function PolicyVersionChip({ profile }: { profile: PolicyProfile }) {
  return (
    <HoverCard openDelay={120}>
      <HoverCardTrigger asChild>
        <button
          type="button"
          className="inline-flex items-center gap-1.5 font-mono text-[10.5px] uppercase tracking-[0.18em] text-muted-foreground transition-colors hover:text-foreground"
        >
          <Info className="h-3 w-3" />
          {profile.version}
        </button>
      </HoverCardTrigger>
      <HoverCardContent side="left" align="end" className="w-[280px] text-[12.5px]">
        <div className="space-y-1.5">
          <Kv k="Version" v={profile.version ?? "—"} />
          <Kv k="Rule pack" v={profile.rule_pack ?? "—"} />
        </div>
      </HoverCardContent>
    </HoverCard>
  );
}

function PolicyCardSkeleton() {
  return (
    <div className="rounded-xl border bg-card p-4">
      <Skeleton className="h-3 w-16" />
      <Skeleton className="mt-3 h-7 w-24" />
      <Skeleton className="mt-3 h-3 w-full" />
      <Skeleton className="mt-1.5 h-3 w-3/4" />
    </div>
  );
}

function PolicyCard({
  profile,
  active,
  pending,
  disabled,
  onActivate,
}: {
  profile: PolicyProfileDef;
  active: boolean;
  pending: boolean;
  disabled: boolean;
  onActivate: () => void;
}) {
  const steps = STEP_DOTS[profile.id];

  return (
    <button
      type="button"
      onClick={onActivate}
      disabled={disabled}
      className={cn(
        "group relative flex flex-col overflow-hidden rounded-xl border text-left transition-shadow duration-200",
        "disabled:pointer-events-none disabled:opacity-60",
        active
          ? cn(
              "bg-brand-gradient border-brand-dark text-brand-foreground",
              "shadow-[inset_0_1px_0_rgba(255,255,255,0.10),inset_0_0_0_1px_rgba(255,255,255,0.04),0_10px_30px_-8px_rgba(21,40,34,0.45)]",
              "hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.14),inset_0_0_0_1px_rgba(255,255,255,0.06),0_18px_48px_-10px_rgba(21,40,34,0.55)]",
            )
          : cn(
              "bg-card",
              "shadow-[inset_0_1px_0_rgba(255,255,255,0.8),0_1px_2px_rgba(15,17,21,0.04)]",
              "hover:border-foreground/15 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.8),0_6px_18px_-6px_rgba(15,17,21,0.10)]",
            ),
      )}
    >
      {pending && (
        <span className="absolute inset-x-0 bottom-0 h-px overflow-hidden">
          <span
            className={cn(
              "block h-full w-1/3 animate-[shimmer_1.2s_linear_infinite]",
              active ? "bg-white" : "bg-foreground",
            )}
          />
        </span>
      )}

      <div className="flex items-center justify-between px-5 pt-4">
        <StepDots filled={steps} active={active} />
        <div className="flex items-center gap-2">
          {profile.recommended && !pending && (
            <span
              className={cn(
                "font-mono text-[9.5px] font-medium uppercase tracking-[0.18em]",
                active ? "text-white/70" : "text-muted-foreground",
              )}
            >
              Recommended
            </span>
          )}
          {pending && (
            <span
              className={cn(
                "inline-flex items-center gap-1 font-mono text-[9.5px] uppercase tracking-[0.18em]",
                active ? "text-white/70" : "text-muted-foreground",
              )}
            >
              <Loader2 className="h-3 w-3 animate-spin" />
              Activating
            </span>
          )}
        </div>
      </div>

      <div className="px-5 pt-2.5">
        <div className="text-[22px] font-semibold leading-tight tracking-tight">
          {profile.label}
        </div>
        <p
          className={cn(
            "mt-1 text-[12.5px] leading-snug",
            active ? "text-white/85" : "text-foreground/80",
          )}
        >
          {profile.lede}
        </p>
        <p
          className={cn(
            "mt-0.5 text-[11.5px] leading-snug",
            active ? "text-white/55" : "text-muted-foreground",
          )}
        >
          {profile.hint}
        </p>
      </div>

      <div
        className={cn(
          "mt-3 border-t px-5 py-2.5 font-mono text-[10px] uppercase tracking-[0.22em]",
          active ? "border-white/15 text-white" : "border-border text-muted-foreground/70",
        )}
      >
        {active ? "Active profile" : "Tap to activate"}
      </div>
    </button>
  );
}

function StepDots({ filled, active }: { filled: number; active: boolean }) {
  return (
    <div className="flex items-center gap-1" aria-hidden="true">
      {[1, 2, 3].map((n) => (
        <span
          key={n}
          className={cn(
            "h-1 w-2.5 rounded-full transition-colors",
            n <= filled
              ? active
                ? "bg-white"
                : "bg-foreground"
              : active
                ? "bg-white/25"
                : "bg-muted-foreground/25",
          )}
        />
      ))}
    </div>
  );
}
