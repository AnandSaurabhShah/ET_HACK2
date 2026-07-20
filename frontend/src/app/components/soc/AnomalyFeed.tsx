import { Activity, AlertTriangle, Radio } from "lucide-react";
import type { SocAlert } from "../../lib/api";
import { Button } from "../ui/button";

interface Props {
  alerts: SocAlert[];
  selectedId?: string;
  onSelect: (alert: SocAlert) => void;
  onRun: (alertId: string) => void;
}

const severityClass: Record<string, string> = {
  low: "border-border bg-card",
  medium: "border-yellow-500/50 bg-yellow-500/5",
  high: "border-orange-500/60 bg-orange-500/5",
  critical: "border-accent bg-accent/5",
};

export function AnomalyFeed({ alerts, selectedId, onSelect, onRun }: Props) {
  return (
    <section className="min-h-[420px] border-r border-border/70 pr-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="flex items-center gap-2 text-[15px] font-semibold text-foreground">
          <Radio className="size-4" /> Behavioural Anomaly Feed
        </h2>
        <span className="font-mono text-[11px] text-muted-foreground">{alerts.length} OPEN</span>
      </div>
      <div className="grid max-h-[680px] gap-3 overflow-auto pr-1">
        {alerts.map((alert) => (
          <article
            key={alert.alert_id}
            className={[
              "rounded-sm border p-3 text-left transition-colors",
              severityClass[alert.severity],
              selectedId === alert.alert_id ? "shadow-[0_0_0_2px_var(--ring)]" : "",
            ].join(" ")}
          >
            <button onClick={() => onSelect(alert)} className="block w-full text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="font-mono text-[11px] tracking-wide text-muted-foreground">
                    {alert.alert_id} · {alert.event.segment}
                  </p>
                  <h3 className="mt-1 text-[14px] font-semibold text-foreground">{alert.title}</h3>
                </div>
                <span className="rounded-sm bg-muted px-2 py-1 font-mono text-[11px] uppercase text-foreground">
                  {alert.severity}
                </span>
              </div>
              <dl className="mt-3 grid grid-cols-3 gap-2 text-[12px]">
                <div>
                  <dt className="text-muted-foreground">Score</dt>
                  <dd className="font-mono text-foreground">{Math.round(alert.anomaly_score * 100)}%</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Latency</dt>
                  <dd className="font-mono text-foreground">{Math.round(alert.event.latency_ms)}ms</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Bytes</dt>
                  <dd className="font-mono text-foreground">{Math.round(alert.event.bytes_out)}</dd>
                </div>
              </dl>
            </button>
            <Button size="sm" variant="outline" className="mt-3 h-8 border-border/70" onClick={() => onRun(alert.alert_id)}>
              <Activity className="size-3.5" /> Run playbook
            </Button>
          </article>
        ))}
        {!alerts.length && (
          <div className="rounded-sm border border-border/70 bg-card p-5 text-[13px] text-muted-foreground">
            <AlertTriangle className="mb-2 size-4" /> No alerts returned. Start the backend and run `python seed.py`.
          </div>
        )}
      </div>
    </section>
  );
}

