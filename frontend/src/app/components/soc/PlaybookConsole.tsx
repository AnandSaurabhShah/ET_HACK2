import { CheckCircle2, ClipboardList } from "lucide-react";
import type { PlaybookRun } from "../../lib/api";
import { Button } from "../ui/button";

interface Props {
  runs: PlaybookRun[];
  onApprove: (runId: string) => void;
}

export function PlaybookConsole({ runs, onApprove }: Props) {
  return (
    <section className="rounded-sm border border-border/70 bg-card p-4">
      <h2 className="mb-3 flex items-center gap-2 text-[15px] font-semibold text-foreground">
        <ClipboardList className="size-4" /> SOAR Playbook Console
      </h2>
      <div className="grid gap-3">
        {runs.map((run) => (
          <div key={run.run_id} className="rounded-sm border border-border/70 bg-background p-3">
            <div className="flex items-center justify-between gap-3">
              <div>
                <p className="font-mono text-[11px] text-muted-foreground">{run.run_id} · {run.alert_id}</p>
                <p className="text-[13px] font-semibold text-foreground">{run.status.replaceAll("_", " ")}</p>
              </div>
              {run.status === "queued_for_approval" && (
                <Button size="sm" className="h-8" onClick={() => onApprove(run.run_id)}>
                  <CheckCircle2 className="size-3.5" /> Approve
                </Button>
              )}
            </div>
            <div className="mt-3 grid gap-2">
              {run.steps.map((step) => (
                <div key={`${run.run_id}-${step.action}`} className="rounded-sm bg-muted px-2 py-1 text-[12px]">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-foreground">{step.name}</span>
                    <span className="font-mono text-muted-foreground">
                      BR {step.blast_radius} · {step.status} · {step.verified ? "verified" : "unverified"}
                    </span>
                  </div>
                  {step.details && <p className="mt-1 line-clamp-2 text-[11px] text-muted-foreground">{step.details}</p>}
                </div>
              ))}
            </div>
          </div>
        ))}
        {!runs.length && <p className="text-[13px] text-muted-foreground">Run a playbook from an alert to populate the console.</p>}
      </div>
    </section>
  );
}
