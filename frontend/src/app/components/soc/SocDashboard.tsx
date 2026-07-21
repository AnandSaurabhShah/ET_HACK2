import { useEffect, useMemo, useState } from "react";
import { Database, Gauge, History, LockKeyhole, Radar, ShieldCheck, TimerReset, Zap } from "lucide-react";
import {
  alertsEventSource,
  api,
  type AuditEntry,
  type ConnectorInfo,
  type CopilotAnswer,
  type IncidentTimeline,
  type MitreCoverage,
  type PlaybookRun,
  type SocAlert,
  type SocMetricReport,
  type ZeroDayStrategy,
} from "../../lib/api";
import { AnomalyFeed } from "./AnomalyFeed";
import { AttackAttribution } from "./AttackAttribution";
import { ConnectorReadiness } from "./ConnectorReadiness";
import { PlaybookConsole } from "./PlaybookConsole";
import { CveQueue } from "./CveQueue";
import { DigitalTwin } from "./DigitalTwin";
import { IncidentTimeline as IncidentTimelinePanel } from "./IncidentTimeline";
import { MitreCoverage as MitreCoveragePanel } from "./MitreCoverage";
import { SocCopilot } from "./SocCopilot";
import { ZeroDayPrevention } from "./ZeroDayPrevention";

function pct(n?: number) {
  return `${Math.round((n ?? 0) * 1000) / 10}%`;
}

function Metric({ icon: Icon, label, value, sub }: { icon: typeof Gauge; label: string; value: string; sub: string }) {
  return (
    <div className="rounded-sm border border-border/70 bg-card p-3">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[12px] text-muted-foreground">{label}</span>
        <Icon className="size-4 text-primary" />
      </div>
      <div className="mt-2 font-mono text-[20px] text-foreground">{value}</div>
      <div className="mt-1 text-[11px] text-muted-foreground">{sub}</div>
    </div>
  );
}

function Capability({ icon: Icon, title, text }: { icon: typeof Gauge; title: string; text: string }) {
  return (
    <div className="rounded-sm border border-border/70 bg-card p-3">
      <div className="flex items-center gap-2 text-[12px] font-semibold text-foreground">
        <Icon className="size-4 text-primary" /> {title}
      </div>
      <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">{text}</p>
    </div>
  );
}

export function SocDashboard() {
  const [report, setReport] = useState<SocMetricReport | null>(null);
  const [alerts, setAlerts] = useState<SocAlert[]>([]);
  const [selectedId, setSelectedId] = useState<string>();
  const [runs, setRuns] = useState<PlaybookRun[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [cves, setCves] = useState<any[]>([]);
  const [graph, setGraph] = useState<any>(null);
  const [simulation, setSimulation] = useState<any>(null);
  const [coverage, setCoverage] = useState<MitreCoverage | null>(null);
  const [timeline, setTimeline] = useState<IncidentTimeline | null>(null);
  const [connectors, setConnectors] = useState<ConnectorInfo[]>([]);
  const [copilot, setCopilot] = useState<CopilotAnswer | null>(null);
  const [zeroDayStrategy, setZeroDayStrategy] = useState<ZeroDayStrategy | null>(null);
  const [error, setError] = useState<string | null>(null);

  const selected = useMemo(() => alerts.find((a) => a.alert_id === selectedId) ?? alerts[0], [alerts, selectedId]);

  async function refresh() {
    try {
      const [reportRes, alertsRes, auditRes, cveRes, graphRes, coverageRes, connectorRes, zeroDayRes] = await Promise.all([
        api.report(),
        api.alerts(),
        api.audit(),
        api.cves(),
        api.graph(),
        api.coverage(),
        api.connectors(),
        api.zeroDayStrategy(),
      ]);
      setReport(reportRes);
      setAlerts(alertsRes.items);
      setAudit(auditRes.items);
      setCves(cveRes.items);
      setGraph(graphRes);
      setCoverage(coverageRes);
      setConnectors(connectorRes.items);
      setZeroDayStrategy(zeroDayRes);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to reach backend");
    }
  }

  useEffect(() => {
    void refresh();
    let events: EventSource | null = null;
    let reconnect: number | undefined;
    const connect = () => {
      events?.close();
      events = alertsEventSource();
      events.addEventListener("alert", (event) => {
        const alert = JSON.parse((event as MessageEvent).data) as SocAlert;
        setAlerts((current) => [alert, ...current.filter((item) => item.alert_id !== alert.alert_id)].slice(0, 30));
      });
      events.onerror = () => {
        events?.close();
        reconnect = window.setTimeout(connect, 2500);
      };
    };
    connect();
    const timer = window.setInterval(() => void refresh(), 15000);
    return () => {
      events?.close();
      if (reconnect) window.clearTimeout(reconnect);
      window.clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    if (!selected?.alert_id) {
      setTimeline(null);
      return;
    }
    void api.timeline(selected.alert_id).then(setTimeline).catch(() => setTimeline(null));
  }, [selected?.alert_id]);

  async function runPlaybook(alertId: string) {
    const run = await api.runPlaybook(alertId);
    setRuns((current) => [run, ...current.filter((item) => item.run_id !== run.run_id)]);
    const auditRes = await api.audit();
    setAudit(auditRes.items);
  }

  async function approve(runId: string) {
    const run = await api.approvePlaybook(runId);
    setRuns((current) => current.map((item) => (item.run_id === runId ? run : item)));
    const auditRes = await api.audit();
    setAudit(auditRes.items);
  }

  async function simulate() {
    setSimulation(await api.simulateTwin());
    const auditRes = await api.audit();
    setAudit(auditRes.items);
  }

  async function askCopilot(question: string) {
    setCopilot(await api.askCopilot(question, selected?.alert_id));
    const auditRes = await api.audit();
    setAudit(auditRes.items);
  }

  return (
    <main className="mx-auto max-w-7xl px-4 py-6">
      <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="font-mono text-[11px] tracking-wide text-muted-foreground">AEGIS-CNI - SECURITY ROLE</p>
          <h1 style={{ fontFamily: "var(--font-serif)" }} className="mt-1 text-[24px] text-foreground">
            SOC Command Center
          </h1>
          <p className="mt-1 max-w-2xl text-[13px] text-muted-foreground">
            Live request-layer detection, ATT&CK attribution, SOAR containment, CVE prioritisation, and auditability for the exam platform.
          </p>
        </div>
        <span className="rounded-sm border border-border/70 bg-card px-3 py-2 font-mono text-[11px] text-muted-foreground">
          API {api.base}
        </span>
      </div>

      <div className="mb-5 grid gap-3 md:grid-cols-3">
        <Capability icon={Zap} title="Live-Only Attack Surface" text="The dashboard defaults to live terminal/API attacks, not looping sample noise. Manual simulations remain explicit." />
        <Capability icon={ShieldCheck} title="Prediction Before Known CVE" text="Behavioural ML scores rare sequences and unknown exploit patterns before a database match exists." />
        <Capability icon={LockKeyhole} title="Mitigation With Audit" text="High-confidence sources are blocked, risky actions require approval, and every response is hash-chained." />
      </div>

      {error && <div className="mb-4 rounded-sm border border-accent bg-accent/5 p-3 text-[13px] text-foreground">Backend unavailable: {error}</div>}

      <div className="mb-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-6">
        <Metric icon={Radar} label="Detection" value={pct(report?.detection_rate)} sub={`${report?.alert_count ?? 0} eval alerts`} />
        <Metric icon={Gauge} label="False Positive" value={pct(report?.false_positive_rate)} sub="eval harness" />
        <Metric icon={ShieldCheck} label="ATT&CK Accuracy" value={pct(report?.attack_technique_accuracy)} sub={`${report?.mitre_technique_count ?? 0} MITRE techniques`} />
        <Metric icon={TimerReset} label="MTTD" value={`${report?.mttd_minutes ?? 0}m`} sub={`${report?.mttd_improvement ?? 0}x faster`} />
        <Metric icon={History} label="MTTR" value={`${report?.mttr_minutes ?? 0}m`} sub={`${report?.mttr_improvement ?? 0}x faster`} />
        <Metric icon={Database} label="Autonomous" value={`${report?.autonomous_playbook_percent ?? 0}%`} sub="playbook steps" />
      </div>

      <div className="grid gap-5 lg:grid-cols-[minmax(360px,0.9fr)_minmax(480px,1.1fr)]">
        <AnomalyFeed alerts={alerts} selectedId={selected?.alert_id} onSelect={(a) => setSelectedId(a.alert_id)} onRun={(id) => void runPlaybook(id)} />
        <div className="grid gap-4">
          <MitreCoveragePanel coverage={coverage} />
          <AttackAttribution alert={selected} />
          <ZeroDayPrevention strategy={zeroDayStrategy} />
          <IncidentTimelinePanel timeline={timeline} />
          <SocCopilot alert={selected} answer={copilot} onAsk={askCopilot} />
          <PlaybookConsole runs={runs} onApprove={(id) => void approve(id)} />
          <CveQueue items={cves} />
          <ConnectorReadiness items={connectors} />
          <DigitalTwin graph={graph} simulation={simulation} onSimulate={() => void simulate()} />
          <section className="rounded-sm border border-border/70 bg-card p-4">
            <h2 className="mb-3 text-[15px] font-semibold text-foreground">Hash-Chained Audit Trail</h2>
            <div className="max-h-[260px] overflow-auto">
              <table className="w-full min-w-[720px] text-left text-[12px]">
                <thead className="border-b border-border/70 text-muted-foreground">
                  <tr>
                    <th className="py-2 font-medium">#</th>
                    <th className="py-2 font-medium">Actor</th>
                    <th className="py-2 font-medium">Action</th>
                    <th className="py-2 font-medium">Hash</th>
                  </tr>
                </thead>
                <tbody>
                  {audit.map((entry) => (
                    <tr key={entry.hash} className="border-b border-border/40">
                      <td className="py-2 font-mono text-muted-foreground">{entry.index}</td>
                      <td className="py-2 text-foreground">{entry.actor}</td>
                      <td className="py-2 text-foreground">{entry.action}</td>
                      <td className="py-2 font-mono text-muted-foreground">{entry.hash.slice(0, 18)}...</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      </div>
    </main>
  );
}
