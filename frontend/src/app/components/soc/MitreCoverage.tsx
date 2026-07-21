import { Grid2X2, ShieldAlert } from "lucide-react";
import type { MitreCoverage as MitreCoverageData } from "../../lib/api";

function pct(part: number, total: number) {
  return `${Math.round((part / Math.max(1, total)) * 100)}%`;
}

export function MitreCoverage({ coverage }: { coverage?: MitreCoverageData | null }) {
  if (!coverage) {
    return (
      <section className="rounded-sm border border-border/70 bg-card p-4 text-[13px] text-muted-foreground">
        Loading ATT&CK coverage.
      </section>
    );
  }
  return (
    <section className="rounded-sm border border-border/70 bg-card p-4">
      <h2 className="mb-3 flex items-center gap-2 text-[15px] font-semibold text-foreground">
        <Grid2X2 className="size-4" /> ATT&CK Coverage Heatmap
      </h2>
      <div className="mb-3 grid grid-cols-4 gap-2 text-[11px]">
        <div className="rounded-sm bg-muted p-2">
          <p className="text-muted-foreground">Corpus</p>
          <p className="font-mono text-foreground">{coverage.summary.total}</p>
        </div>
        <div className="rounded-sm bg-accent/10 p-2">
          <p className="text-muted-foreground">Live</p>
          <p className="font-mono text-foreground">{coverage.summary.active_live}</p>
        </div>
        <div className="rounded-sm bg-primary/10 p-2">
          <p className="text-muted-foreground">RAG</p>
          <p className="font-mono text-foreground">{coverage.summary.attribution_ready}</p>
        </div>
        <div className="rounded-sm bg-yellow-500/10 p-2">
          <p className="text-muted-foreground">Adapters</p>
          <p className="font-mono text-foreground">{coverage.summary.needs_connector}</p>
        </div>
      </div>
      <div className="grid max-h-[260px] gap-2 overflow-auto pr-1">
        {coverage.tactics.map((tactic) => (
          <div key={tactic.tactic} className="rounded-sm border border-border/70 bg-background p-2">
            <div className="mb-1 flex items-center justify-between gap-2">
              <span className="text-[12px] font-medium text-foreground">{tactic.tactic.replaceAll("-", " ")}</span>
              <span className="font-mono text-[11px] text-muted-foreground">{tactic.total}</span>
            </div>
            <div className="flex h-2 overflow-hidden rounded-sm bg-muted">
              <div className="bg-accent" style={{ width: pct(tactic.active_live, tactic.total) }} />
              <div className="bg-yellow-500" style={{ width: pct(tactic.needs_connector, tactic.total) }} />
              <div className="bg-primary" style={{ width: pct(tactic.attribution_ready, tactic.total) }} />
            </div>
          </div>
        ))}
      </div>
      <p className="mt-3 flex items-center gap-2 text-[11px] text-muted-foreground">
        <ShieldAlert className="size-3.5" /> Green means active live detection; yellow needs SIEM/EDR/IAM/OT adapters; blue is attribution/simulation ready.
      </p>
    </section>
  );
}
