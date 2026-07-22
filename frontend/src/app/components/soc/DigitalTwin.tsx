import { GitBranch, Play } from "lucide-react";
import { Button } from "../ui/button";

export function DigitalTwin({ graph, simulation, onSimulate }: { graph: any; simulation: any; onSimulate: () => void }) {
  const nodes = graph?.nodes ?? [];
  const edges = graph?.edges ?? [];
  const path = new Set(simulation?.path ?? []);
  return (
    <section className="rounded-sm border border-border/70 bg-card p-4">
      <div className="mb-3 flex items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-[15px] font-semibold text-foreground">
          <GitBranch className="size-4" /> Cyber Resilience Digital Twin
        </h2>
        <Button size="sm" variant="outline" className="h-8 border-border/70" onClick={onSimulate}>
          <Play className="size-3.5" /> Simulate
        </Button>
      </div>
      <div className="relative min-h-[220px] rounded-sm border border-border/70 bg-background p-3">
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
          {nodes.map((node: any) => (
            <div
              key={node.id}
              className={[
                "rounded-sm border px-3 py-2 text-[12px]",
                path.has(node.id) ? "border-accent bg-accent/10 text-foreground" : "border-border/70 bg-muted text-muted-foreground",
              ].join(" ")}
            >
              <div className="font-semibold text-foreground">{node.label}</div>
              <div className="font-mono text-[11px]">
                {node.kind} - risk {Math.round((node.risk ?? 0) * 100)}%
              </div>
              <div className="mt-2 h-1.5 rounded-sm bg-background">
                <div className="h-1.5 rounded-sm bg-primary" style={{ width: `${Math.round((node.live_pressure ?? 0) * 100)}%` }} />
              </div>
              <div className="mt-2 line-clamp-2 text-[10px]">{(node.controls ?? []).slice(0, 2).join(", ")}</div>
            </div>
          ))}
        </div>
        <p className="mt-3 font-mono text-[11px] text-muted-foreground">
          {edges.length} modelled control edges - {graph?.blocked_sources ?? 0} blocked sources - simulated model only
        </p>
        {simulation && (
          <div className="mt-3 rounded-sm border border-border/70 bg-card p-3 text-[11px] text-muted-foreground">
            <div className="mb-2 flex items-center justify-between gap-2 font-mono text-foreground">
              <span>What-if risk</span>
              <span>
                {Math.round((simulation.risk_before ?? 0) * 100)}% -&gt; {Math.round((simulation.risk_after ?? 0) * 100)}%
              </span>
            </div>
            <div className="grid gap-1">
              {(simulation.recommended_controls ?? []).slice(0, 4).map((item: string) => (
                <span key={item}>{item}</span>
              ))}
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
