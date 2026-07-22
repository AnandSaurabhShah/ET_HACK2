import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Activity, Database, Gauge, LockKeyhole, Radio, ShieldCheck, TimerReset, Zap } from "lucide-react";
import {
  alertsEventSource,
  api,
  type AuditEntry,
  type BlockEntry,
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
import { ActiveBlocks } from "./ActiveBlocks";
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

function displayScore(alert?: SocAlert) {
  const scores = alert?.event.metadata?.model_scores as Record<string, number> | undefined;
  return scores?.decision_score ?? alert?.anomaly_score ?? 0;
}

function requestBytes(alert?: SocAlert) {
  if (!alert) return 0;
  return Number(alert.event.metadata?.request_size ?? alert.event.bytes_out ?? 0);
}

function formatBytes(value: number) {
  if (value >= 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${Math.round(value)} B`;
}

function avg(rows: number[]) {
  return rows.length ? rows.reduce((sum, value) => sum + value, 0) / rows.length : 0;
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
  const [blocks, setBlocks] = useState<BlockEntry[]>([]);
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
  const [streamState, setStreamState] = useState<"connecting" | "live" | "retrying">("connecting");
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [livePulse, setLivePulse] = useState(0);

  const selected = useMemo(() => alerts.find((a) => a.alert_id === selectedId) ?? alerts[0], [alerts, selectedId]);
  const selectedIdRef = useRef<string | undefined>();

  useEffect(() => {
    selectedIdRef.current = selected?.alert_id;
  }, [selected?.alert_id]);

  const liveStats = useMemo(() => {
    const scores = alerts.map(displayScore);
    const latencies = alerts.map((alert) => alert.event.latency_ms);
    const bytes = alerts.map(requestBytes);
    const critical = alerts.filter((alert) => alert.severity === "critical").length;
    const contained = alerts.filter((alert) => alert.status === "contained" || alert.status === "queued").length;
    const techniques = new Set(alerts.flatMap((alert) => alert.attribution.techniques.map((technique) => technique.id)));
    return {
      count: alerts.length,
      avgScore: avg(scores),
      avgLatency: avg(latencies),
      avgBytes: avg(bytes),
      critical,
      contained,
      techniques: techniques.size,
      latest: alerts[0],
    };
  }, [alerts]);

  const refreshDynamic = useCallback(async (timelineAlertId?: string) => {
    try {
      const [alertsRes, auditRes, cveRes, graphRes] = await Promise.all([
        api.alerts(),
        api.audit(),
        api.cves(),
        api.graph(),
      ]);
      const blocksRes = await api.blocks();
      setAlerts(alertsRes.items);
      setAudit(auditRes.items);
      setCves(cveRes.items);
      setGraph(graphRes);
      setBlocks(blocksRes.items);
      const nextTimelineAlertId = timelineAlertId ?? selectedIdRef.current ?? alertsRes.items[0]?.alert_id;
      if (nextTimelineAlertId) {
        setTimeline(await api.timeline(nextTimelineAlertId));
      } else {
        setTimeline(null);
      }
      setLastRefresh(new Date());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to reach backend");
    }
  }, []);

  const refresh = useCallback(async () => {
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
      const blocksRes = await api.blocks();
      setReport(reportRes);
      setAlerts(alertsRes.items);
      setAudit(auditRes.items);
      setCves(cveRes.items);
      setGraph(graphRes);
      setCoverage(coverageRes);
      setConnectors(connectorRes.items);
      setZeroDayStrategy(zeroDayRes);
      setBlocks(blocksRes.items);
      const nextTimelineAlertId = selectedIdRef.current ?? alertsRes.items[0]?.alert_id;
      if (nextTimelineAlertId) {
        setTimeline(await api.timeline(nextTimelineAlertId));
      } else {
        setTimeline(null);
      }
      setLastRefresh(new Date());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to reach backend");
    }
  }, []);

  useEffect(() => {
    void refresh();
    let events: EventSource | null = null;
    let reconnect: number | undefined;
    const connect = () => {
      events?.close();
      events = alertsEventSource();
      setStreamState("connecting");
      events.onopen = () => setStreamState("live");
      events.addEventListener("alert", (event) => {
        const alert = JSON.parse((event as MessageEvent).data) as SocAlert;
        setAlerts((current) => [alert, ...current.filter((item) => item.alert_id !== alert.alert_id)].slice(0, 30));
        setSelectedId(alert.alert_id);
        setCopilot(null);
        setLivePulse((current) => current + 1);
        setLastRefresh(new Date());
        void refreshDynamic(alert.alert_id);
      });
      events.onerror = () => {
        setStreamState("retrying");
        events?.close();
        reconnect = window.setTimeout(connect, 2500);
      };
    };
    connect();
    const dynamicTimer = window.setInterval(() => void refreshDynamic(selectedIdRef.current), 5000);
    const staticTimer = window.setInterval(() => void refresh(), 60000);
    return () => {
      events?.close();
      if (reconnect) window.clearTimeout(reconnect);
      window.clearInterval(dynamicTimer);
      window.clearInterval(staticTimer);
    };
  }, [refresh, refreshDynamic]);

  useEffect(() => {
    if (!selected?.alert_id) {
      setTimeline(null);
      return;
    }
    void api.timeline(selected.alert_id).then((nextTimeline) => {
      setTimeline(nextTimeline);
      setLastRefresh(new Date());
    }).catch(() => setTimeline(null));
  }, [selected?.alert_id]);

  async function runPlaybook(alertId: string) {
    const run = await api.runPlaybook(alertId);
    setRuns((current) => [run, ...current.filter((item) => item.run_id !== run.run_id)]);
    const auditRes = await api.audit();
    setAudit(auditRes.items);
    await refreshDynamic(alertId);
  }

  async function blockSource(alertId: string) {
    await api.blockAlertSource(alertId);
    await refreshDynamic(alertId);
  }

  async function unblockIp(ip: string) {
    await api.unblockIp(ip);
    await refreshDynamic(selected?.alert_id);
  }

  async function approve(runId: string) {
    const run = await api.approvePlaybook(runId);
    setRuns((current) => current.map((item) => (item.run_id === runId ? run : item)));
    const auditRes = await api.audit();
    setAudit(auditRes.items);
    await refreshDynamic(selected?.alert_id);
  }

  async function simulate() {
    setSimulation(await api.simulateTwin());
    const auditRes = await api.audit();
    setAudit(auditRes.items);
    await refreshDynamic(selected?.alert_id);
  }

  async function askCopilot(question: string) {
    setCopilot(await api.askCopilot(question, selected?.alert_id));
    const auditRes = await api.audit();
    setAudit(auditRes.items);
    setLastRefresh(new Date());
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
          {streamState.toUpperCase()} - API {api.base}
        </span>
      </div>

      <div className="mb-5 grid gap-3 md:grid-cols-3">
        <Capability icon={Zap} title="Live-Only Attack Surface" text="The dashboard defaults to live terminal/API attacks, not looping sample noise. Manual simulations remain explicit." />
        <Capability icon={ShieldCheck} title="Prediction Before Known CVE" text="Behavioural ML scores rare sequences and unknown exploit patterns before a database match exists." />
        <Capability icon={LockKeyhole} title="Mitigation With Audit" text="High-confidence sources are blocked, risky actions require approval, and every response is hash-chained." />
      </div>

      {error && <div className="mb-4 rounded-sm border border-accent bg-accent/5 p-3 text-[13px] text-foreground">Backend unavailable: {error}</div>}

      <div className="mb-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-6">
        <Metric icon={Radio} label="Live Alerts" value={`${liveStats.count}`} sub={`pulse ${livePulse} - ${streamState}`} />
        <Metric icon={Gauge} label="Avg Risk Score" value={pct(liveStats.avgScore)} sub={liveStats.latest ? `${liveStats.latest.alert_id} latest` : "waiting for live attack"} />
        <Metric icon={TimerReset} label="Avg Latency" value={`${Math.round(liveStats.avgLatency)}ms`} sub={liveStats.latest ? `${Math.round(liveStats.latest.event.latency_ms)}ms latest` : "live request timing"} />
        <Metric icon={Database} label="Avg Req Bytes" value={formatBytes(liveStats.avgBytes)} sub={liveStats.latest ? `${formatBytes(requestBytes(liveStats.latest))} latest` : "live request size"} />
        <Metric icon={ShieldCheck} label="Active Blocks" value={`${blocks.length}`} sub={`${liveStats.techniques} ATT&CK techniques`} />
        <Metric icon={Activity} label="Contained/Queued" value={`${liveStats.contained}`} sub={`baseline ${pct(report?.detection_rate)} detection`} />
      </div>

      <div className="mb-5 rounded-sm border border-border/70 bg-card px-3 py-2 text-[12px] text-muted-foreground">
        Last live sync: {lastRefresh ? lastRefresh.toLocaleTimeString() : "waiting"} - Alerts, attribution, timeline, CVE queue,
        digital twin, audit trail, and metrics refresh from the same live backend data.
      </div>

      <div className="grid gap-5 lg:grid-cols-[minmax(360px,0.9fr)_minmax(480px,1.1fr)]">
        <AnomalyFeed alerts={alerts} selectedId={selected?.alert_id} onSelect={(a) => setSelectedId(a.alert_id)} onRun={(id) => void runPlaybook(id)} onBlock={(id) => void blockSource(id)} />
        <div className="grid gap-4">
          <MitreCoveragePanel coverage={coverage} />
          <AttackAttribution alert={selected} />
          <ActiveBlocks items={blocks} onUnblock={(ip) => void unblockIp(ip)} />
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
