import { Skeleton } from "@/components/ui/skeleton";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
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

  return (
    <header className="flex items-center justify-between gap-4 border-b bg-background px-10 py-5">
      <div className="flex min-w-0 items-center gap-3">
        {loading ? (
          <Skeleton className="h-6 w-60" />
        ) : (
          <>
            <span className="relative flex h-2 w-2 shrink-0">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-brand opacity-50" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-brand" />
            </span>
            <span className="truncate font-mono text-[17px] font-medium tracking-tight text-foreground">
              {session?.session_id ?? "-"}
            </span>
          </>
        )}
      </div>

      <Tooltip>
        <TooltipTrigger asChild>
          <span className="cursor-default text-[11.5px] text-muted-foreground">
            {modeLabel}
          </span>
        </TooltipTrigger>
        <TooltipContent side="bottom">{modeHint}</TooltipContent>
      </Tooltip>
    </header>
  );
}
