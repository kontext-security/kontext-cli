import { Skeleton } from "@/components/ui/skeleton";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { decisionTone } from "./helpers";
import type { Counts, Decision, Tab } from "./types";

const TILES: { id: Tab; label: string }[] = [
  { id: "all", label: "Total" },
  { id: "deny", label: "Would deny" },
  { id: "ask", label: "Needs ask" },
  { id: "allow", label: "Allowed" },
];

const RATIO_KINDS: { kind: Decision; label: string }[] = [
  { kind: "deny", label: "Would deny" },
  { kind: "ask", label: "Ask" },
  { kind: "allow", label: "Allow" },
];

export function StatRow({
  counts,
  active,
  onSelect,
  loading,
}: {
  counts: Counts;
  active: Tab;
  onSelect: (t: Tab) => void;
  loading: boolean;
}) {
  return (
    <section className="overflow-hidden rounded-xl border bg-card shadow-[inset_0_1px_0_rgba(255,255,255,0.8),0_1px_2px_rgba(0,0,0,0.04)]">
      <div className="grid grid-cols-2 divide-x divide-y md:grid-cols-4 md:divide-y-0">
        {TILES.map((t) => (
          <StatTile
            key={t.id}
            id={t.id}
            label={t.label}
            count={counts[t.id]}
            total={counts.all}
            active={active === t.id}
            loading={loading}
            onClick={() => onSelect(t.id)}
          />
        ))}
      </div>
      <RatioStrip counts={counts} />
    </section>
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
  id: Tab;
  label: string;
  count: number;
  total: number;
  active: boolean;
  loading: boolean;
  onClick: () => void;
}) {
  const pct = id === "all" ? null : Math.round((count / Math.max(1, total)) * 100);
  const numberColor =
    count === 0
      ? "text-muted-foreground/40"
      : id === "all"
        ? ""
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
            "font-mono text-[10px] font-medium uppercase tracking-[0.22em]",
            active ? "text-foreground" : "text-muted-foreground",
          )}
        >
          {label}
        </span>
        <span className="mt-1 text-[11px] text-muted-foreground/70">
          {pct == null ? "Decisions captured" : `${pct}% of session`}
        </span>
      </div>
    </button>
  );
}

function RatioStrip({ counts }: { counts: Counts }) {
  const segments = RATIO_KINDS.map((k) => ({
    count: counts[k.kind],
    color: decisionTone[k.kind].bg,
    label: k.label,
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
        <div className="flex items-center gap-3 font-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground">
          {segments.length === 0 ? (
            <span>No activity yet</span>
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
