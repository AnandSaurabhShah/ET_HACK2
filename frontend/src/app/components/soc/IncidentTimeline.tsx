import { ListChecks } from "lucide-react";
import type { IncidentTimeline as IncidentTimelineData } from "../../lib/api";

export function IncidentTimeline({ timeline }: { timeline?: IncidentTimelineData | null }) {
  return (
    <section className="rounded-sm border border-border/70 bg-card p-4">
      <h2 className="mb-3 flex items-center gap-2 text-[15px] font-semibold text-foreground">
        <ListChecks className="size-4" /> Incident Timeline
      </h2>
      {!timeline?.items?.length ? (
        <p className="text-[13px] text-muted-foreground">Select a live alert to replay detection, attribution, containment, and audit steps.</p>
      ) : (
        <ol className="grid max-h-[300px] gap-2 overflow-auto pr-1">
          {timeline.items.map((item, index) => (
            <li key={`${item.stage}-${item.timestamp}-${index}`} className="rounded-sm border border-border/70 bg-background p-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-[12px] font-medium text-foreground">{item.title}</span>
                <span className="font-mono text-[10px] uppercase text-muted-foreground">{item.status}</span>
              </div>
              <p className="mt-1 text-[11px] text-muted-foreground">{item.detail}</p>
              <p className="mt-1 font-mono text-[10px] text-muted-foreground">
                {new Date(item.timestamp).toLocaleTimeString()} {item.actor ? `- ${item.actor}` : ""}
              </p>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
