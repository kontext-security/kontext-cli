import { useState } from "react";
import { ChevronDown, Shield, X } from "lucide-react";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { decisionLabel, decisionSource, decisionTone, prettyTool, summaryOf } from "./helpers";
import { DecisionDot } from "./shared";
import type { Decision, Event, EventGroups, LogView, ObservedActivityEvent, Tab } from "./types";

const VISIBLE_KINDS = {
  all: ["deny", "allow"],
  deny: ["deny"],
  allow: ["allow"],
} satisfies Record<Tab, readonly Decision[]>;

export function ActionList({
  tab,
  view,
  decisionGroups,
  observedEvents,
  openId,
  onOpen,
  onViewChange,
  onClearFilter,
}: {
  tab: Tab;
  view: LogView;
  decisionGroups: EventGroups;
  observedEvents: ObservedActivityEvent[];
  openId: string | null;
  onOpen: (id: string) => void;
  onViewChange: (view: LogView) => void;
  onClearFilter: () => void;
}) {
  const visibleDecisionGroups = VISIBLE_KINDS[tab]
    .map((kind) => ({ kind, items: decisionGroups[kind] }))
    .filter(({ items }) => items.length > 0);
  const decisionCount = decisionGroups.allow.length + decisionGroups.deny.length;
  const filterLabel = view === "decisions" && tab !== "all" ? decisionLabel(tab) : null;

  return (
    <section className="min-w-0 overflow-hidden rounded-xl border bg-card shadow-[inset_0_1px_0_rgba(255,255,255,0.8),0_1px_2px_rgba(0,0,0,0.04)]">
      <div className="flex min-w-0 flex-wrap items-center justify-between gap-3 border-b px-5 py-3">
        <div className="inline-flex shrink-0 items-center rounded-lg bg-muted p-1">
          <LogTab
            active={view === "decisions"}
            label="Decision Log"
            count={decisionCount}
            onClick={() => onViewChange("decisions")}
          />
          <LogTab
            active={view === "observed"}
            label="Observed Activity"
            count={observedEvents.length}
            onClick={() => onViewChange("observed")}
          />
        </div>

        {filterLabel && (
          <button
            type="button"
            onClick={onClearFilter}
            className="inline-flex h-7 items-center gap-1.5 rounded-md border bg-background px-2.5 text-[12px] text-muted-foreground transition-colors hover:text-foreground"
          >
            <span>Filtered: <span className="text-foreground">{filterLabel}</span></span>
            <X className="h-3 w-3" />
          </button>
        )}
      </div>

      <div className="grid">
        <div
          className={cn(
            "col-start-1 row-start-1 min-w-0",
            view !== "decisions" && "hidden",
          )}
          aria-hidden={view !== "decisions"}
        >
          {decisionCount === 0 ? (
            <Empty
              title="No decisions captured yet."
              description="Pre-tool Guard decisions will appear here."
            />
          ) : visibleDecisionGroups.length === 0 ? (
            <Empty
              title={`No ${filterLabel?.toLowerCase() ?? "matching"} decisions.`}
              description="Clear the filter to show all decisions."
            />
          ) : (
            visibleDecisionGroups.map(({ kind, items }, index) => (
              <Group
                key={kind}
                label={decisionLabel(kind)}
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
            view !== "observed" && "hidden",
          )}
          aria-hidden={view !== "observed"}
        >
          {observedEvents.length === 0 ? (
            <Empty
              title="No observed activity yet."
              description="Post-execution tool activity will appear here."
            />
          ) : (
            <Group label="Observed Activity" count={observedEvents.length}>
              {observedEvents.map((e) => (
                <Row key={e.id} event={e} active={openId === e.id} onClick={() => onOpen(e.id)} />
              ))}
            </Group>
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
  onClick,
}: {
  active: boolean;
  label: string;
  count: number;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        "inline-flex h-7 items-center gap-1.5 rounded-md px-3 text-[12px] font-medium transition-colors",
        active
          ? "bg-background text-foreground shadow-sm"
          : "text-muted-foreground hover:text-foreground",
      )}
    >
      <span>{label}</span>
      <span
        className={cn(
          "tabular-nums text-[11px] font-normal",
          active ? "text-muted-foreground" : "text-muted-foreground/60",
        )}
      >
        {count}
      </span>
    </button>
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
  count,
  separated = false,
  children,
}: {
  label: string;
  count: number;
  separated?: boolean;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(true);
  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <CollapsibleTrigger
        className={cn(
          "flex w-full items-center gap-2 border-b bg-muted/40 px-5 py-2.5 text-left text-[13px] font-medium text-muted-foreground transition-colors hover:bg-muted/40",
          separated && "border-t",
        )}
      >
        <ChevronDown
          className={cn("h-3 w-3 transition-transform", !open && "-rotate-90")}
        />
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
        "group relative grid w-full grid-cols-[10px_minmax(0,1fr)_auto] items-center gap-4 border-b px-10 py-3 text-left transition-colors last:border-b-0",
        "hover:bg-muted/40",
        active && "bg-accent",
      )}
    >
      {active && <span className="absolute inset-y-0 left-0 w-[2px] bg-brand" />}
      <DecisionDot kind={event.decision} />
      <span className="flex min-w-0 items-baseline gap-2.5">
        <span className="text-[12px] font-medium text-foreground">{prettyTool(event.tool_name)}</span>
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
