import { useState } from "react";
import { ChevronDown, Shield } from "lucide-react";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { decisionTone, prettyTool, scoreLabel, summaryOf } from "./helpers";
import { DecisionDot } from "./shared";
import type { Decision, Event, EventGroups, Tab } from "./types";

const TITLES: Record<Tab, string> = {
  all: "All actions",
  deny: "Denied · this session",
  ask: "Needs ask · this session",
  allow: "Allowed · this session",
};

const GROUP_LABELS: Record<Decision, string> = {
  deny: "Would deny",
  ask: "Needs ask",
  allow: "Allow",
};

const VISIBLE_KINDS: Record<Tab, Decision[]> = {
  all: ["deny", "ask", "allow"],
  deny: ["deny"],
  ask: ["ask"],
  allow: ["allow"],
};

export function ActionList({
  tab,
  groups,
  openId,
  onOpen,
  hasAny,
}: {
  tab: Tab;
  groups: EventGroups;
  openId: string | null;
  onOpen: (id: string) => void;
  hasAny: boolean;
}) {
  return (
    <section className="overflow-hidden rounded-xl border bg-card shadow-[inset_0_1px_0_rgba(255,255,255,0.8),0_1px_2px_rgba(0,0,0,0.04)]">
      <div className="flex items-center justify-between gap-3 border-b px-5 py-3">
        <div className="flex items-baseline gap-2.5">
          <h3 className="font-mono text-[10.5px] font-medium uppercase tracking-[0.22em] text-muted-foreground">
            {TITLES[tab]}
          </h3>
          {tab !== "all" && (
            <span className="text-[11px] text-muted-foreground/80">
              Click <span className="text-foreground">Total</span> to clear
            </span>
          )}
        </div>
      </div>

      {!hasAny ? (
        <Empty />
      ) : (
        <div>
          {VISIBLE_KINDS[tab].map((kind) => {
            const items = groups[kind];
            if (items.length === 0) return null;
            return (
              <Group key={kind} label={GROUP_LABELS[kind]} kind={kind} count={items.length}>
                {items.map((e) => (
                  <Row key={e.id} event={e} active={openId === e.id} onClick={() => onOpen(e.id)} />
                ))}
              </Group>
            );
          })}
        </div>
      )}
    </section>
  );
}

function Empty() {
  return (
    <div className="flex flex-col items-center gap-2 px-8 py-16 text-center text-muted-foreground">
      <Shield className="h-5 w-5 text-muted-foreground/50" />
      <p className="text-[13px]">No actions captured yet.</p>
      <p className="text-[12px] text-muted-foreground/70">
        Start Claude Code to populate this view.
      </p>
    </div>
  );
}

function Group({
  label,
  kind,
  count,
  children,
}: {
  label: string;
  kind: Decision;
  count: number;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(true);
  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <CollapsibleTrigger className="flex w-full items-center gap-2 border-b bg-muted/20 px-5 py-2 text-left text-[12px] font-medium text-muted-foreground transition-colors hover:bg-muted/40">
        <ChevronDown
          className={cn("h-3 w-3 transition-transform", !open && "-rotate-90")}
        />
        <DecisionDot kind={kind} />
        <span className="text-foreground">{label}</span>
        <span className="tabular-nums text-[11px] text-muted-foreground">{count}</span>
      </CollapsibleTrigger>
      <CollapsibleContent className="overflow-hidden data-[state=closed]:animate-collapsible-up data-[state=open]:animate-collapsible-down">
        <div className="ml-8 border-l border-border/80">{children}</div>
      </CollapsibleContent>
    </Collapsible>
  );
}

function Row({
  event,
  active,
  onClick,
}: {
  event: Event;
  active: boolean;
  onClick: () => void;
}) {
  const target = summaryOf(event);
  const signal = event.risk_event?.signals?.[0]?.replace(/_/g, " ");
  const tone = decisionTone[event.decision];
  return (
    <button
      onClick={onClick}
      className={cn(
        "group relative grid w-full grid-cols-[10px_minmax(0,1fr)_auto] items-center gap-4 border-b px-4 py-3 text-left transition-colors last:border-b-0",
        "hover:bg-muted/40",
        active && "bg-accent",
      )}
    >
      {active && <span className="absolute inset-y-0 left-0 w-[2px] bg-brand" />}
      <DecisionDot kind={event.decision} />
      <span className="flex min-w-0 items-baseline gap-2.5">
        <span className="text-[13px] font-medium text-foreground">{prettyTool(event.tool_name)}</span>
        <span className="truncate font-mono text-[12px] text-muted-foreground">{target}</span>
      </span>
      <span className="flex items-center gap-3">
        {signal && (
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="hidden max-w-[180px] truncate text-[11px] text-muted-foreground md:inline">
                {signal}
              </span>
            </TooltipTrigger>
            <TooltipContent side="top">Primary signal: {signal}</TooltipContent>
          </Tooltip>
        )}
        <span
          className={cn(
            "rounded-md border bg-background/60 px-1.5 py-0.5 font-mono text-[11px] font-medium tabular-nums",
            tone.border,
            event.decision === "allow" ? "text-muted-foreground" : tone.text,
          )}
        >
          {scoreLabel(event)}
        </span>
        <ChevronDown
          className={cn(
            "h-3 w-3 -rotate-90 text-muted-foreground/0 transition-all group-hover:text-muted-foreground/70",
            active && "text-muted-foreground/70",
          )}
        />
      </span>
    </button>
  );
}
