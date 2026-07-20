import { Crosshair, ExternalLink, ShieldCheck } from "lucide-react";
import type { SocAlert } from "../../lib/api";

export function AttackAttribution({ alert }: { alert?: SocAlert }) {
  if (!alert) {
    return (
      <section className="rounded-sm border border-border/70 bg-card p-4 text-[13px] text-muted-foreground">
        Select an alert to inspect ATT&CK attribution.
      </section>
    );
  }
  const modelScores = alert.event.metadata?.model_scores as Record<string, number> | undefined;
  const prediction = alert.event.metadata?.prediction as { reasons?: string[]; predicted_next_stage?: string } | undefined;
  return (
    <section className="rounded-sm border border-border/70 bg-card p-4">
      <h2 className="mb-3 flex items-center gap-2 text-[15px] font-semibold text-foreground">
        <Crosshair className="size-4" /> MITRE ATT&CK Attribution
      </h2>
      <div className="grid gap-3">
        {alert.attribution.techniques.map((technique) => (
          <div key={technique.id} className="rounded-sm border border-border/70 bg-background p-3">
            <div className="flex items-start justify-between gap-3">
              <div>
                <h3 className="text-[14px] font-semibold text-foreground">
                  {technique.id} · {technique.name}
                </h3>
                <p className="mt-1 font-mono text-[11px] uppercase tracking-wide text-muted-foreground">
                  {technique.tactics.join(" · ") || "ATT&CK technique"}
                </p>
              </div>
              {technique.url && (
                <a href={technique.url} target="_blank" rel="noreferrer" className="text-primary" aria-label={`Open ${technique.id}`}>
                  <ExternalLink className="size-4" />
                </a>
              )}
            </div>
            <p className="mt-2 line-clamp-3 text-[12px] text-muted-foreground">{technique.description}</p>
            <div className="mt-3 flex flex-wrap gap-1">
              {(technique.mitigations.length ? technique.mitigations : ["Mitigation guidance unavailable in local subset"]).slice(0, 4).map((m) => (
                <span key={m} className="rounded-sm bg-muted px-2 py-1 text-[11px] text-foreground">
                  <ShieldCheck className="mr-1 inline size-3" /> {m}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
      <div className="mt-3 rounded-sm bg-muted p-3 text-[12px] text-foreground">
        <p>
          <span className="font-semibold">Confidence:</span> {Math.round(alert.attribution.confidence * 100)}%
        </p>
        <p className="mt-1">
          <span className="font-semibold">Likely next stage:</span> {alert.attribution.likely_next_stage}
        </p>
        <p className="mt-1">
          <span className="font-semibold">Recommendation:</span> {alert.attribution.recommendation}
        </p>
        {modelScores && (
          <p className="mt-1">
            <span className="font-semibold">AI risk:</span> anomaly {Math.round((modelScores.anomaly_score ?? 0) * 100)}%, predictive{" "}
            {Math.round((modelScores.predictive_risk_score ?? 0) * 100)}%
          </p>
        )}
        {prediction?.reasons?.length ? (
          <ul className="mt-2 grid gap-1">
            {prediction.reasons.slice(0, 4).map((reason) => (
              <li key={reason} className="text-muted-foreground">
                {reason}
              </li>
            ))}
          </ul>
        ) : null}
      </div>
    </section>
  );
}
