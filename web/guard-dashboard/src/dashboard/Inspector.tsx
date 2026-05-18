import { ScrollArea } from "@/components/ui/scroll-area";
import { SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { cn } from "@/lib/utils";
import {
  actionSummary,
  decisionLabel,
  decisionSource,
  decisionTone,
  humanize,
  humanReason,
  prettyTool,
  summaryOf,
  technicalExplanation,
} from "./helpers";
import { Dd, DecisionDot, Dt } from "./shared";
import type { Event } from "./types";

export function Inspector({ event }: { event: Event }) {
  const r = event.risk_event ?? {};
  const tone = decisionTone[event.decision];

  return (
    <div className="flex h-full flex-col bg-background">
      <SheetHeader className="flex flex-row items-center gap-2 border-b bg-background px-6 py-3.5 pr-14 space-y-0">
        <DecisionDot kind={event.decision} />
        <SheetTitle className={cn("text-[13px] font-medium", tone.text)}>
          {decisionLabel(event.decision)}
        </SheetTitle>
        <span className="ml-2 font-mono text-[10.5px] uppercase tracking-[0.2em] text-muted-foreground">
          {prettyTool(event.tool_name)}
        </span>
      </SheetHeader>

      <ScrollArea className="flex-1">
        <div className="space-y-7 px-7 py-7">
          <div className="space-y-3">
            <pre className="whitespace-pre-wrap break-words font-mono text-[15px] font-medium leading-snug tracking-tight text-foreground">
              {summaryOf(event)}
            </pre>
            <p className="text-[13.5px] leading-relaxed text-foreground/75">
              {humanReason(event)}
            </p>
          </div>

          <dl className="grid grid-cols-[120px_1fr] gap-y-3 text-[13px]">
            <Dt>Operation</Dt>
            <Dd>{r.operation || r.operation_class || "unknown"}</Dd>
            <Dt>Source</Dt>
            <Dd>{decisionSource(event)}</Dd>
            <Dt>Stage</Dt>
            <Dd>{r.decision_stage ? humanize(r.decision_stage) : "unknown"}</Dd>
            <Dt>Environment</Dt>
            <Dd>
              <span className="font-mono text-[12.5px]">{r.environment || "unknown"}</span>
            </Dd>
            {r.judge_model && (
              <>
                <Dt>Judge</Dt>
                <Dd>{r.judge_model}</Dd>
              </>
            )}
            {r.policy_rule_id && (
              <>
                <Dt>Policy rule</Dt>
                <Dd>{r.policy_rule_id}</Dd>
              </>
            )}
          </dl>

          <Section title="Analysis">
            <p className="text-[13px] leading-relaxed text-foreground/80">
              {technicalExplanation(event)}
            </p>
          </Section>

          <Section title="Command">
            <pre className="overflow-x-auto rounded-md border bg-muted/40 px-3 py-2.5 font-mono text-[12px] leading-relaxed text-foreground/90">
              {actionSummary(event)}
            </pre>
          </Section>

          {(r.signals ?? []).length > 0 && (
            <Section title="Signals">
              <div className="flex flex-wrap gap-1.5">
                {(r.signals ?? []).map((s) => (
                  <span
                    key={s}
                    className="inline-flex items-center gap-1.5 rounded-md border bg-card px-2 py-1 font-mono text-[11px] text-foreground/80 shadow-[inset_0_1px_0_rgba(255,255,255,0.7)]"
                  >
                    <span className={cn("h-1 w-1 rounded-full", tone.bg)} />
                    {humanize(s)}
                  </span>
                ))}
              </div>
            </Section>
          )}

          {event.reason_code && (
            <div className="border-t pt-4 font-mono text-[10.5px] uppercase tracking-[0.2em] text-muted-foreground">
              reason · <span className="text-foreground/70">{event.reason_code}</span>
            </div>
          )}
        </div>
      </ScrollArea>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-2.5">
      <h3 className="font-mono text-[10px] font-medium uppercase tracking-[0.22em] text-muted-foreground">
        {title}
      </h3>
      {children}
    </div>
  );
}
