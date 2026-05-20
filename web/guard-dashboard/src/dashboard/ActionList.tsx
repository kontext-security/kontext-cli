import { useState } from "react";
import { ChevronDown, Info, Shield } from "lucide-react";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { decisionSource, decisionTone, prettyTool, summaryOf } from "./helpers";
import { DecisionDot } from "./shared";
import type { Decision, Event, EventGroups, Tab } from "./types";

type LogView = "decisions" | "observed";

const TITLES: Record<Tab, string> = {
  all: "All decisions",
  deny: "Would deny · this session",
  allow: "Allow · this session",
};

const GROUP_LABELS: Record<Decision, string> = {
  deny: "Would deny",
  allow: "Allow",
};

const VISIBLE_KINDS: Record<Tab, Decision[]> = {
  all: ["deny", "allow"],
  deny: ["deny"],
  allow: ["allow"],
};

export function ActionList({
  tab,
  view,
  decisionGroups,
  observedEvents,
  openId,
  onOpen,
  onViewChange,
}: {
  tab: Tab;
  view: LogView;
  decisionGroups: EventGroups;
  observedEvents: Event[];
  openId: string | null;
  onOpen: (id: string) => void;
  onViewChange: (view: LogView) => void;
}) {
  const visibleDecisionGroups = VISIBLE_KINDS[tab]
    .map((kind) => ({ kind, items: decisionGroups[kind] }))
    .filter(({ items }) => items.length > 0);
  const decisionCount = decisionGroups.allow.length + decisionGroups.deny.length;

  return (
    <section className="min-w-0 overflow-hidden rounded-xl border bg-card shadow-[inset_0_1px_0_rgba(255,255,255,0.8),0_1px_2px_rgba(0,0,0,0.04)]">
      <div className="flex min-w-0 flex-wrap items-center justify-between gap-3 border-b px-5 py-3">
        <div className="flex min-w-0 items-baseline gap-2.5">
          <h3 className="font-mono text-[10.5px] font-medium uppercase tracking-[0.22em] text-muted-foreground">
            {view === "decisions" ? TITLES[tab] : "Observed events"}
          </h3>
          {view === "decisions" && tab !== "all" && (
            <span className="text-[11px] text-muted-foreground/80">
              Click <span className="text-foreground">Total</span> to clear
            </span>
          )}
        </div>

        <div className="flex max-w-full shrink-0 items-center gap-1 rounded-md border bg-muted/30 p-0.5">
          <LogTab
            active={view === "decisions"}
            label="Decision Log"
            count={decisionCount}
            help="Pre-tool Guard decisions only. These rows are actual authorization decisions: allow or would deny, with policy source, reason, and details."
            onClick={() => onViewChange("decisions")}
          />
          <LogTab
            active={view === "observed"}
            label="Observed Activity"
            count={observedEvents.length}
            help="Post-execution tool activity recorded for context. These rows are observations, not enforcement decisions."
            onClick={() => onViewChange("observed")}
          />
        </div>
      </div>

      <div className="grid">
        <div
          className={cn(
            "col-start-1 row-start-1 min-w-0",
            view !== "decisions" && "invisible pointer-events-none",
          )}
          aria-hidden={view !== "decisions"}
        >
          {decisionCount === 0 ? (
            <Empty
              title="No decisions captured yet."
              description="Pre-tool Guard decisions will appear here."
            />
          ) : (
            visibleDecisionGroups.map(({ kind, items }, index) => (
              <Group
                key={kind}
                label={GROUP_LABELS[kind]}
                kind={kind}
                count={items.length}
                separated={index > 0}
              >
                {items.map((e) => (
                  <Row key={e.id} event={e} active={openId === e.id} onClick={() => onOpen(e.id)} />
                ))}
              </Group>
            ))
          )}
        </div>
        <div
          className={cn(
            "col-start-1 row-start-1 min-w-0",
            view !== "observed" && "invisible pointer-events-none",
          )}
          aria-hidden={view !== "observed"}
        >
          {observedEvents.length === 0 ? (
            <Empty
              title="No observed activity yet."
              description="Post-execution tool activity will appear here."
            />
          ) : (
            observedEvents.map((e) => (
              <Row key={e.id} event={e} active={openId === e.id} onClick={() => onOpen(e.id)} />
            ))
          )}
        </div>
      </div>
    </section>
  );
}

function LogTab({
  active,
  label,
  count,
  help,
  onClick,
}: {
  active: boolean;
  label: string;
  count: number;
  help: string;
  onClick: () => void;
}) {
  return (
    <div className="flex min-w-0 items-center">
      <button
        type="button"
        onClick={onClick}
        className={cn(
          "inline-flex h-7 min-w-0 items-center gap-1.5 rounded px-2.5 text-[12px] font-medium transition-colors",
          active
            ? "bg-background text-foreground shadow-sm"
            : "text-muted-foreground hover:text-foreground",
        )}
      >
        <span className="truncate">{label}</span>
        <span className="font-mono text-[10.5px] text-muted-foreground">{count}</span>
      </button>
      <Tooltip>
        <TooltipTrigger asChild>
          <button
            type="button"
            aria-label={`${label} help`}
            className="mr-1 inline-flex h-7 w-5 shrink-0 items-center justify-center rounded text-muted-foreground transition-colors hover:text-foreground"
          >
            <Info className="h-3.5 w-3.5" />
          </button>
        </TooltipTrigger>
        <TooltipContent side="top" className="max-w-[320px] text-[12px] leading-relaxed">
          {help}
        </TooltipContent>
      </Tooltip>
    </div>
  );
}

function Empty({
  title = "No decisions captured yet.",
  description = "Start Claude Code to populate this view.",
}: {
  title?: string;
  description?: string;
}) {
  return (
    <div className="flex min-h-[320px] flex-col items-center justify-center gap-2 px-8 py-16 text-center text-muted-foreground">
      <Shield className="h-5 w-5 text-muted-foreground/50" />
      <p className="text-[13px]">{title}</p>
      <p className="text-[12px] text-muted-foreground/70">{description}</p>
    </div>
  );
}

function Group({
  label,
  kind,
  count,
  separated,
  children,
}: {
  label: string;
  kind: Decision;
  count: number;
  separated: boolean;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(true);
  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <CollapsibleTrigger
        className={cn(
          "flex w-full items-center gap-2 border-b bg-muted/40 px-5 py-2 text-left text-[12px] font-medium text-muted-foreground transition-colors hover:bg-muted/40",
          separated && "border-t",
        )}
      >
        <ChevronDown
          className={cn("h-3 w-3 transition-transform", !open && "-rotate-90")}
        />
        <DecisionDot kind={kind} />
        <span className="text-foreground">{label}</span>
        <span className="tabular-nums text-[11px] text-muted-foreground">{count}</span>
      </CollapsibleTrigger>
      <CollapsibleContent className="overflow-hidden data-[state=closed]:animate-collapsible-up data-[state=open]:animate-collapsible-down">
        <div>{children}</div>
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
        "group relative grid w-full grid-cols-[10px_minmax(0,1fr)_auto] items-center gap-4 border-b px-8 py-3 text-left transition-colors last:border-b-0",
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
            "rounded-md border bg-background/60 px-1.5 py-0.5 font-mono text-[10.5px] font-medium",
            tone.border,
            event.decision === "allow" ? "text-muted-foreground" : tone.text,
          )}
        >
          {decisionSource(event)}
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
