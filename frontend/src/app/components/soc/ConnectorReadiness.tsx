import { Cable } from "lucide-react";
import type { ConnectorInfo } from "../../lib/api";

export function ConnectorReadiness({ items }: { items: ConnectorInfo[] }) {
  return (
    <section className="rounded-sm border border-border/70 bg-card p-4">
      <h2 className="mb-3 flex items-center gap-2 text-[15px] font-semibold text-foreground">
        <Cable className="size-4" /> Production Connectors
      </h2>
      <div className="grid max-h-[280px] gap-2 overflow-auto pr-1">
        {items.map((item) => (
          <div key={item.name} className="rounded-sm border border-border/70 bg-background p-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-[12px] font-medium text-foreground">{item.name}</span>
              <span className="rounded-sm bg-muted px-2 py-0.5 font-mono text-[10px] uppercase text-muted-foreground">{item.category}</span>
            </div>
            <p className="mt-1 text-[11px] text-muted-foreground">{item.production_target}</p>
            <p className="mt-1 font-mono text-[10px] text-primary">{item.implemented_interface.join(" / ")}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
