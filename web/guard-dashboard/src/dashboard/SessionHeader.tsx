import { Skeleton } from "@/components/ui/skeleton";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { dateTime } from "./helpers";
import type { Session } from "./types";

export function SessionHeader({
  session,
  loading,
}: {
  session?: Session;
  loading: boolean;
}) {
  const mode = session?.mode ?? "observe";
  const modeLabel = mode === "enforce" ? "Enforce mode" : "Observe mode";
  const modeHint =
    mode === "enforce"
      ? "Blocking deny decisions before the tool runs."
      : "Recording decisions but not enforcing them.";
  const closed = session?.status === "closed" || Boolean(session?.closed_at);
  const startedAt = dateTime(session?.created_at ?? session?.latest_at);
  const endedAt = dateTime(session?.closed_at);

  return (
    <header className="flex items-center justify-between gap-4 border-b bg-background px-10 py-5">
      <div className="flex min-w-0 items-center gap-3">
        {loading ? (
          <Skeleton className="h-6 w-60" />
        ) : (
          <>
            <span className="relative flex h-2 w-2 shrink-0">
              {!closed && (
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-brand opacity-50" />
              )}
              <span
                className={cn(
                  "relative inline-flex h-2 w-2 rounded-full",
                  closed ? "bg-muted-foreground/45" : "bg-brand",
                )}
              />
            </span>
            <span className="truncate font-mono text-[17px] font-medium tracking-tight text-foreground">
              {session?.session_id ?? "-"}
            </span>
          </>
        )}
      </div>

      <div className="flex shrink-0 flex-wrap items-center justify-end gap-2 text-[11.5px] text-muted-foreground">
        {startedAt && (
          <LifecycleBadge
            label="Started"
            value={startedAt}
            tone="active"
          />
        )}
        {endedAt && (
          <LifecycleBadge
            label="Ended"
            value={endedAt}
            tone="closed"
          />
        )}
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="cursor-default whitespace-nowrap">{modeLabel}</span>
          </TooltipTrigger>
          <TooltipContent side="bottom">{modeHint}</TooltipContent>
        </Tooltip>
      </div>
    </header>
  );
}

function LifecycleBadge({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone: "active" | "closed";
}) {
  return (
    <span
      className={cn(
        "inline-flex h-8 items-center gap-2 whitespace-nowrap rounded-md border px-2.5 shadow-sm",
        tone === "active"
          ? "border-brand/30 bg-brand/5 text-brand"
          : "border-muted-foreground/25 bg-muted/60 text-muted-foreground",
      )}
    >
      <span className="text-[10px] font-semibold uppercase tracking-wide">{label}</span>
      <span className="font-mono text-[11px] text-foreground">{value}</span>
    </span>
  );
}
