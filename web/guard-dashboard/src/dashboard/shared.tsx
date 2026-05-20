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
  children,
}: {
  label?: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="mt-8 first:mt-0">
      {(label || description) && (
        <div className="mb-3.5 flex items-baseline gap-3">
          {label && (
            <h2 className="text-[15px] font-semibold tracking-tight">{label}</h2>
          )}
          {description && (
            <span className="text-[12.5px] text-muted-foreground">{description}</span>
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
    <dt className="self-center break-words text-[12px] text-muted-foreground [overflow-wrap:anywhere]">
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
