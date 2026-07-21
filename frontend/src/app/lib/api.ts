const API_BASE = import.meta.env.VITE_AEGIS_API_URL ?? "http://localhost:8000";
const API_KEY = import.meta.env.VITE_AEGIS_API_KEY;

export interface ApiList<T> {
  items: T[];
  total?: number;
}

export interface SocMetricReport {
  dataset_rows: number;
  labelled_attack_rows: number;
  alert_count: number;
  detection_rate: number;
  false_positive_rate: number;
  attack_technique_accuracy: number;
  mttd_minutes: number;
  manual_mttd_minutes: number;
  mttd_improvement: number;
  mttr_minutes: number;
  manual_mttr_minutes: number;
  mttr_improvement: number;
  autonomous_playbook_percent: number;
  mitre_technique_count?: number;
  observed_techniques: string[];
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactics: string[];
  description: string;
  mitigations: string[];
  url: string;
}

export interface SocAlert {
  alert_id: string;
  anomaly_score: number;
  severity: "low" | "medium" | "high" | "critical";
  title: string;
  status: "open" | "contained" | "queued";
  event: {
    event_id: string;
    timestamp: string;
    user_id: string;
    role: string;
    device_id: string;
    segment: string;
    ip: string;
    event_type: string;
    success: boolean;
    latency_ms: number;
    bytes_out: number;
    label: string;
    attack_id?: string;
    technique_id?: string;
    metadata?: Record<string, unknown>;
  };
  attribution: {
    alert_id: string;
    techniques: MitreTechnique[];
    confidence: number;
    evidence: string[];
    likely_next_stage: string;
    recommendation: string;
  };
}

export interface PlaybookRun {
  run_id: string;
  alert_id: string;
  status: "executed" | "queued_for_approval" | "approved";
  autonomous_percent: number;
  justification: string;
  steps: { name: string; action: string; blast_radius: number; status: string; verified?: boolean; details?: string }[];
}

export interface AuditEntry {
  index: number;
  timestamp: string;
  actor: string;
  action: string;
  justification: string;
  blast_radius: number;
  previous_hash: string;
  hash: string;
}

export interface MitreCoverage {
  summary: { total: number; active_live: number; attribution_ready: number; needs_connector: number; connectors: number };
  tactics: { tactic: string; total: number; active_live: number; attribution_ready: number; needs_connector: number }[];
  techniques: { id: string; name: string; tactics: string[]; status: string; reason: string; url: string }[];
}

export interface IncidentTimeline {
  alert_id: string;
  items: { stage: string; timestamp: string; title: string; detail: string; status: string; actor?: string; hash?: string }[];
}

export interface ConnectorInfo {
  name: string;
  category: string;
  status: string;
  production_target: string;
  implemented_interface: string[];
  required_for: string[];
}

export interface CopilotAnswer {
  answer: string;
  evidence: string[];
  recommended_actions: string[];
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(API_KEY ? { "X-Aegis-Api-Key": API_KEY } : {}),
      ...(init?.headers ?? {}),
    },
    ...init,
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export const api = {
  base: API_BASE,
  report: () => request<SocMetricReport>("/eval/report"),
  alerts: () => request<ApiList<SocAlert>>("/alerts?source=live_traffic&limit=30"),
  audit: () => request<ApiList<AuditEntry>>("/audit?limit=20"),
  coverage: () => request<MitreCoverage>("/coverage/mitre"),
  timeline: (alertId: string) => request<IncidentTimeline>(`/incidents/${alertId}/timeline`),
  connectors: () => request<ApiList<ConnectorInfo>>("/integrations/connectors"),
  askCopilot: (question: string, alertId?: string) =>
    request<CopilotAnswer>("/copilot/ask", { method: "POST", body: JSON.stringify({ question, alert_id: alertId }) }),
  cves: () => request<ApiList<any>>("/cve-queue"),
  graph: () => request<any>("/twin/graph"),
  simulateTwin: () => request<any>("/twin/simulate", { method: "POST" }),
  simulateAttack: (techniqueId = "T1110", count = 8) =>
    request<any>(`/simulate/attack/${techniqueId}?count=${count}`, { method: "POST" }),
  demoStatus: () => request<any>("/demo/status"),
  pauseDemo: () => request<any>("/demo/pause", { method: "POST" }),
  resumeDemo: () => request<any>("/demo/resume", { method: "POST" }),
  runPlaybook: (alertId: string) => request<PlaybookRun>(`/playbooks/${alertId}/run`, { method: "POST" }),
  approvePlaybook: (runId: string) => request<PlaybookRun>(`/playbooks/${runId}/approve`, { method: "POST" }),
  ingestEvent: (body: Record<string, unknown>) =>
    fetch(`${API_BASE}/ingest/events`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }).catch(() => undefined),
};

export function alertsEventSource() {
  return new EventSource(`${API_BASE}/alerts/stream?source=live_traffic`);
}
