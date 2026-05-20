import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import type { Session } from "./types";

export function Sidebar({
  sessions,
  currentSession,
  selectedID,
  onSelect,
}: {
  sessions: Session[];
  currentSession?: Session;
  selectedID: string;
  onSelect: (id: string) => void;
}) {
  const currentSessionID = currentSession?.session_id ?? "";
  const otherSessions = sessions.filter((s) => s.session_id !== currentSessionID);
  const sessionRows = currentSession
    ? [currentSession, ...otherSessions].slice(0, 12)
    : sessions.slice(0, 12);

  return (
    <aside className="flex min-h-0 flex-col border-r">
      <div className="px-5 pb-6 pt-7">
        <div className="text-[18px] font-semibold tracking-tight">Kontext</div>
      </div>

      <ScrollArea className="flex-1 px-2">
        {sessionRows.length > 0 && (
          <>
            <div className="px-2.5 pb-1.5 text-[10.5px] font-medium uppercase tracking-[0.18em] text-muted-foreground">
              Sessions
            </div>
            <div className="flex flex-col gap-0.5">
              {sessionRows.map((s) => (
                <SessionButton
                  key={s.session_id}
                  session={s}
                  current={s.session_id === currentSessionID}
                  active={s.session_id === selectedID}
                  onClick={() => onSelect(s.session_id)}
                />
              ))}
            </div>
          </>
        )}
      </ScrollArea>
    </aside>
  );
}

function SessionButton({
  session,
  current,
  active,
  onClick,
}: {
  session: Session;
  current: boolean;
  active?: boolean;
  onClick?: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "flex w-full min-w-0 items-center overflow-hidden rounded-md px-2.5 py-1.5 pr-4 text-left text-[12.5px] transition-colors hover:bg-accent/60",
        active && "bg-accent text-foreground",
      )}
    >
      <span className="flex w-full min-w-0 items-center gap-3 overflow-hidden">
        {current && (
          <span className="shrink-0 rounded-full border border-brand/20 bg-brand/10 px-2 py-0.5 text-[12.5px] font-medium leading-none text-brand-dark">
            This Session
          </span>
        )}
        <span
          className="block min-w-0 flex-1 overflow-hidden text-ellipsis whitespace-nowrap font-mono text-muted-foreground"
          title={session.session_id}
        >
          {session.session_id}
        </span>
      </span>
    </button>
  );
}
