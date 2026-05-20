import { Info } from "lucide-react";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { decisionTone } from "./helpers";
import type { Decision } from "./types";

export function DecisionDot({ kind, className }: { kind: Decision; className?: string }) {
  const tone = decisionTone[kind];
  return (
    <span
      className={cn("h-2 w-2 shrink-0 rounded-full ring-4", tone.bg, tone.ring, className)}
    />
  );
}

export function Block({
  label,
  description,
  help,
  children,
}: {
  label?: string;
  description?: string;
  help?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="mt-8 first:mt-0">
      {(label || description) && (
        <div className="mb-3.5 flex items-baseline gap-3">
          {label && (
            <span className="inline-flex items-center gap-1.5">
              <h2 className="text-[15px] font-semibold tracking-tight">{label}</h2>
              {help && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <button
                      type="button"
                      aria-label={`${label} help`}
                      className="inline-flex h-5 w-5 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
                    >
                      <Info className="h-3.5 w-3.5" />
                    </button>
                  </TooltipTrigger>
                  <TooltipContent side="top" className="max-w-[320px] text-[12px] leading-relaxed">
                    {help}
                  </TooltipContent>
                </Tooltip>
              )}
            </span>
          )}
          {description && (
            <p className="text-[12.5px] text-muted-foreground">{description}</p>
          )}
        </div>
      )}
      {children}
    </section>
  );
}

export function Kv({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex justify-between gap-2">
      <span className="text-muted-foreground">{k}</span>
      <span className="font-mono">{v}</span>
    </div>
  );
}

export function Dt({ children }: { children: React.ReactNode }) {
  return (
    <dt className="self-center break-words text-[10.5px] font-medium uppercase tracking-wider text-muted-foreground [overflow-wrap:anywhere]">
      {children}
    </dt>
  );
}

export function Dd({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <dd className={cn("min-w-0 break-words text-foreground/90 [overflow-wrap:anywhere]", className)}>
      {children}
    </dd>
  );
}
