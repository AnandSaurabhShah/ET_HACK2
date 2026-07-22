from __future__ import annotations

import networkx as nx

from app.models.schemas import Alert


class GraphAgent:
    def __init__(self) -> None:
        self.graph = nx.DiGraph()
        self._build()

    def _build(self) -> None:
        nodes = [
            ("edge-waf", "Perimeter / WAF", "security", 9, ["rate-limit", "signature-block", "trusted-proxy-enforcement"]),
            ("candidate-portal", "Candidate Portal", "portal", 8, ["mfa", "password-policy", "redirect-allowlist"]),
            ("proctoring", "Invigilator Portal", "portal", 7, ["mfa", "role-scope", "session-revocation"]),
            ("marking", "Examiner Marking Portal", "portal", 9, ["mfa", "least-privilege", "audit-trail"]),
            ("certificate-service", "Certificate Verification", "service", 6, ["query-throttling", "redirect-allowlist"]),
            ("auth-db", "Auth DB", "database", 10, ["mfa", "password-policy", "sensitive-password-reuse-block"]),
            ("soc", "SOC Command Center", "security", 10, ["ai-attribution", "soar-approval", "hash-chain-audit"]),
        ]
        for node_id, label, kind, criticality, controls in nodes:
            self.graph.add_node(node_id, label=label, kind=kind, criticality=criticality, controls=controls)
        edges = [
            ("edge-waf", "candidate-portal", "public web traffic"),
            ("edge-waf", "certificate-service", "public certificate lookup"),
            ("candidate-portal", "auth-db", "credential validation"),
            ("proctoring", "auth-db", "staff session"),
            ("marking", "auth-db", "marker session"),
            ("certificate-service", "auth-db", "certificate lookup"),
            ("candidate-portal", "certificate-service", "public lookup abuse"),
            ("auth-db", "marking", "valid account pivot"),
            ("marking", "proctoring", "staff lateral path"),
            ("soc", "auth-db", "containment control"),
        ]
        for source, target, label in edges:
            self.graph.add_edge(source, target, label=label, exposure=0.35 if source == "edge-waf" else 0.6)

    def _node_for_alert(self, alert: Alert) -> str:
        segment = alert.event.segment
        route = str(alert.event.metadata.get("route", ""))
        if "certificate" in segment or "certificate" in route:
            return "certificate-service"
        if segment == "marking":
            return "marking"
        if segment == "proctoring":
            return "proctoring"
        if segment == "soc":
            return "soc"
        if segment == "perimeter":
            return "edge-waf"
        return "candidate-portal"

    def export(self, alerts: list[Alert] | None = None, blocks: list[dict] | None = None) -> dict:
        pressure = {node: 0.0 for node in self.graph.nodes}
        if alerts:
            for alert in alerts[:100]:
                node = self._node_for_alert(alert)
                pressure[node] = min(1.0, pressure[node] + max(alert.anomaly_score, 0.1) / 12)
        blocked_ips = {entry.get("ip") for entry in blocks or []}
        return {
            "nodes": [
                {
                    "id": n,
                    **data,
                    "live_pressure": round(pressure[n], 3),
                    "risk": round(min(1.0, (data["criticality"] / 10) * 0.45 + pressure[n] * 0.55), 3),
                }
                for n, data in self.graph.nodes(data=True)
            ],
            "edges": [{"source": s, "target": t, **data} for s, t, data in self.graph.edges(data=True)],
            "blocked_sources": len(blocked_ips),
            "simulated": True,
            "model": "digital twin reflects live alert pressure, asset criticality, controls, and attack-path exposure.",
        }

    def simulate(self, alerts: list[Alert] | None = None, blocks: list[dict] | None = None) -> dict:
        active_alert = alerts[0] if alerts else None
        if active_alert:
            start = self._node_for_alert(active_alert)
            if start == "edge-waf":
                path = ["edge-waf", "candidate-portal", "auth-db", "marking"]
            elif nx.has_path(self.graph, start, "auth-db"):
                path = nx.shortest_path(self.graph, start, "auth-db")
                if path[-1] == "auth-db":
                    path.extend(["marking", "proctoring"])
            else:
                path = [start, "soc"]
            path = [node for idx, node in enumerate(path) if idx == 0 or node != path[idx - 1]]
        else:
            path = ["edge-waf", "candidate-portal", "auth-db", "marking", "proctoring"]
        live_score = active_alert.anomaly_score if active_alert else 0.62
        blocked_count = len(blocks or [])
        risk_before = min(0.98, live_score + 0.16)
        risk_after = max(0.05, risk_before - 0.22 - min(0.3, blocked_count * 0.03))
        return {
            "path": path,
            "steps": [
                {
                    "node": node,
                    "order": idx + 1,
                    "note": self.graph.nodes[node]["label"],
                    "controls": self.graph.nodes[node]["controls"][:3],
                    "criticality": self.graph.nodes[node]["criticality"],
                }
                for idx, node in enumerate(path)
            ],
            "risk_before": round(risk_before, 3),
            "risk_after": round(risk_after, 3),
            "blocked_sources": blocked_count,
            "recommended_controls": [
                "Keep AI source blocking active at the perimeter.",
                "Require MFA before role-scoped portal access.",
                "Reject unsafe redirects and untrusted forwarding headers.",
                "Preserve hash-chained audit evidence before high-blast-radius isolation.",
            ],
            "label": "SIMULATED digital twin what-if; no live user session or production network is touched.",
        }
