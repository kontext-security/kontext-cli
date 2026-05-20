import { Skeleton } from "@/components/ui/skeleton";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { decisionLabel, decisionTone } from "./helpers";
import type { Counts, Decision, GuardMode, Tab } from "./types";

const DECISION_KINDS: Decision[] = ["deny", "allow"];

export function StatRow({
  counts,
  active,
  onSelect,
  loading,
  mode,
}: {
  counts: Counts;
  active: Tab;
  onSelect: (t: Tab) => void;
  loading: boolean;
  mode: GuardMode;
}) {
  return (
    <section className="overflow-hidden rounded-xl border bg-card shadow-[inset_0_1px_0_rgba(255,255,255,0.8),0_1px_2px_rgba(0,0,0,0.04)]">
      <TotalSummary
        count={counts.all}
        active={active === "all"}
        loading={loading}
        onClick={() => onSelect("all")}
      />
      <div className="grid divide-y md:grid-cols-2 md:divide-x md:divide-y-0">
        {DECISION_KINDS.map((id) => (
          <StatTile
            key={id}
            id={id}
            label={decisionLabel(id, mode)}
            count={counts[id]}
            total={counts.all}
            active={active === id}
            loading={loading}
            onClick={() => onSelect(id)}
          />
        ))}
      </div>
      <RatioStrip counts={counts} mode={mode} />
    </section>
  );
}

function TotalSummary({
  count,
  active,
  loading,
  onClick,
}: {
  count: number;
  active: boolean;
  loading: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label="Show all decisions"
      className={cn(
        "flex w-full items-center gap-3 border-b bg-muted/10 px-6 py-3 text-left transition-colors",
        "hover:bg-muted/30",
        active && "bg-muted/40",
      )}
    >
      {loading ? (
        <Skeleton className="h-7 w-10" />
      ) : (
        <span className="font-mono text-[26px] font-semibold leading-none tabular-nums text-foreground">
          {count}
        </span>
      )}
      <div className="min-w-0">
        <span
          className={cn(
            "text-[13px] font-medium",
            active ? "text-foreground" : "text-muted-foreground",
          )}
        >
          decisions captured
        </span>
      </div>
    </button>
  );
}

function StatTile({
  id,
  label,
  count,
  total,
  active,
  loading,
  onClick,
}: {
  id: Decision;
  label: string;
  count: number;
  total: number;
  active: boolean;
  loading: boolean;
  onClick: () => void;
}) {
  const pct = Math.round((count / Math.max(1, total)) * 100);
  const numberColor =
    count === 0
      ? "text-muted-foreground/40"
      : decisionTone[id].text;
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "group relative flex items-baseline gap-4 px-6 py-5 text-left transition-colors",
        "hover:bg-muted/30",
        active && "bg-muted/40",
      )}
    >
      {loading ? (
        <Skeleton className="h-9 w-12" />
      ) : (
        <span
          className={cn(
            "font-mono text-[36px] font-semibold leading-none tracking-tight tabular-nums",
            numberColor,
          )}
        >
          {count}
        </span>
      )}
      <div className="flex flex-col leading-tight">
        <span
          className={cn(
            "text-[12px] font-medium",
            active ? "text-foreground" : "text-muted-foreground",
          )}
        >
          {label}
        </span>
        <span className="mt-1 text-[11px] text-muted-foreground/70">
          {pct}% of decisions
        </span>
      </div>
    </button>
  );
}

function RatioStrip({ counts, mode }: { counts: Counts; mode: GuardMode }) {
  const segments = DECISION_KINDS.map((kind) => ({
    count: counts[kind],
    color: decisionTone[kind].bg,
    label: decisionLabel(kind, mode),
  })).filter((s) => s.count > 0);

  return (
    <div className="border-t bg-muted/20 px-6 py-3">
      <div className="flex items-center gap-4">
        <div className="flex h-1.5 flex-1 gap-0.5 overflow-hidden rounded-full bg-muted/60">
          {segments.length === 0 ? (
            <div className="w-full bg-muted-foreground/15" />
          ) : (
            segments.map((s) => (
              <Tooltip key={s.label}>
                <TooltipTrigger asChild>
                  <div
                    className={cn("transition-opacity hover:opacity-80", s.color)}
                    style={{ flex: s.count }}
                    aria-label={`${s.count} ${s.label}`}
                  />
                </TooltipTrigger>
                <TooltipContent side="top">
                  {s.count} {s.label.toLowerCase()}
                </TooltipContent>
              </Tooltip>
            ))
          )}
        </div>
        <div className="flex items-center gap-3 text-[11.5px] text-muted-foreground">
          {segments.length === 0 ? (
            <span>No decisions yet</span>
          ) : (
            segments.map((s) => (
              <span key={s.label} className="inline-flex items-center gap-1.5">
                <span className={cn("h-1.5 w-1.5 rounded-full", s.color)} />
                {s.label}
                <span className="tabular-nums text-foreground/70">{s.count}</span>
              </span>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
