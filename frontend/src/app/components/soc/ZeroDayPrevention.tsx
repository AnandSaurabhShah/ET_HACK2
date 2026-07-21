import { ShieldAlert } from "lucide-react";
import type { ZeroDayStrategy } from "../../lib/api";

function label(value: string) {
  return value.replace(/_/g, " ");
}

export function ZeroDayPrevention({ strategy }: { strategy?: ZeroDayStrategy | null }) {
  if (!strategy) {
    return (
      <section className="rounded-sm border border-border/70 bg-card p-4 text-[13px] text-muted-foreground">
        Loading zero-day prevention strategy.
      </section>
    );
  }

  return (
    <section className="rounded-sm border border-border/70 bg-card p-4">
      <h2 className="mb-2 flex items-center gap-2 text-[15px] font-semibold text-foreground">
        <ShieldAlert className="size-4" /> {strategy.name}
      </h2>
      <p className="mb-3 text-[12px] leading-relaxed text-muted-foreground">{strategy.summary}</p>

      <div className="grid gap-2 md:grid-cols-2">
        {strategy.lifecycle.map((stage) => (
          <div key={stage.stage} className="rounded-sm border border-border/70 bg-background p-3">
            <div className="font-mono text-[11px] uppercase text-primary">{label(stage.stage)}</div>
            <p className="mt-1 text-[12px] text-foreground">{stage.defensive_goal}</p>
            <ul className="mt-2 space-y-1 text-[11px] text-muted-foreground">
              {stage.controls.slice(0, 3).map((control) => (
                <li key={control}>{control}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>

      <div className="mt-3 grid gap-3 md:grid-cols-3">
        <div>
          <h3 className="mb-2 text-[12px] font-medium text-foreground">Watch Signals</h3>
          <div className="space-y-1 text-[11px] text-muted-foreground">
            {strategy.watch_signals.slice(0, 4).map((item) => (
              <p key={item}>{item}</p>
            ))}
          </div>
        </div>
        <div>
          <h3 className="mb-2 text-[12px] font-medium text-foreground">ATT&CK Focus</h3>
          <div className="flex flex-wrap gap-1">
            {strategy.mitre_focus.map((item) => (
              <span key={item} className="rounded-sm bg-muted px-2 py-1 font-mono text-[10px] text-foreground">
                {item.split(" ")[0]}
              </span>
            ))}
          </div>
        </div>
        <div>
          <h3 className="mb-2 text-[12px] font-medium text-foreground">Aegis Mapping</h3>
          <div className="space-y-1 text-[11px] text-muted-foreground">
            {strategy.aegis_mapping.slice(0, 4).map((item) => (
              <p key={item}>{item}</p>
            ))}
          </div>
        </div>
      </div>

      <div className="mt-3 border-t border-border/70 pt-3">
        <h3 className="mb-2 text-[12px] font-medium text-foreground">Reference Incidents</h3>
        <div className="grid gap-2 md:grid-cols-2">
          {strategy.example_incidents.map((incident) => (
            <p key={incident.name} className="text-[11px] leading-relaxed text-muted-foreground">
              <span className="font-medium text-foreground">{incident.name}:</span> {incident.lesson}
            </p>
          ))}
        </div>
      </div>
    </section>
  );
}
