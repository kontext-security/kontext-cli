import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import type { Counts, Session } from "./types";

export function Sidebar({
  sessions,
  counts,
  selectedID,
  onSelect,
}: {
  sessions: Session[];
  counts: Counts;
  selectedID: string;
  onSelect: (id: string) => void;
}) {
  return (
    <aside className="flex min-h-0 flex-col border-r">
      <div className="px-5 pb-6 pt-7">
        <div className="text-[18px] font-semibold tracking-tight">Kontext</div>
      </div>

      <ScrollArea className="flex-1 px-2">
        <NavItem label="This session" count={counts.all} active />

        {sessions.length > 1 && (
          <>
            <div className="px-2.5 pb-1.5 pt-6 text-[10.5px] font-medium uppercase tracking-[0.18em] text-muted-foreground">
              Recent
            </div>
            <div className="flex flex-col gap-0.5">
              {sessions.slice(0, 12).map((s) => (
                <button
                  key={s.session_id}
                  type="button"
                  onClick={() => onSelect(s.session_id)}
                  className={cn(
                    "flex items-center justify-between gap-2 rounded-md px-2.5 py-1.5 text-left text-[12.5px] transition-colors hover:bg-accent/60",
                    s.session_id === selectedID && "bg-accent text-foreground",
                  )}
                >
                  <span className="truncate font-mono text-muted-foreground">
                    {s.session_id}
                  </span>
                  <span className="shrink-0 tabular-nums text-[11px] text-muted-foreground">
                    {s.actions}
                  </span>
                </button>
              ))}
            </div>
          </>
        )}
      </ScrollArea>
    </aside>
  );
}

function NavItem({ label, count, active }: { label: string; count: number; active?: boolean }) {
  return (
    <button
      type="button"
      className={cn(
        "flex w-full items-center justify-between rounded-md px-2.5 py-1.5 text-left text-[13px] font-medium transition-colors",
        active
          ? "bg-accent text-foreground"
          : "text-muted-foreground hover:bg-accent/60 hover:text-foreground",
      )}
    >
      <span>{label}</span>
      <span className="font-mono text-[11px] text-muted-foreground">{count}</span>
    </button>
  );
}
