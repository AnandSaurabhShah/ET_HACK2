from __future__ import annotations

import networkx as nx


class GraphAgent:
    def __init__(self) -> None:
        self.graph = nx.DiGraph()
        self._build()

    def _build(self) -> None:
        nodes = [
            ("candidate-portal", "Candidate Portal", "portal"),
            ("proctoring", "Invigilator Portal", "portal"),
            ("marking", "Examiner Marking Portal", "portal"),
            ("certificate-service", "Certificate Verification", "service"),
            ("auth-db", "Auth DB", "database"),
            ("soc", "SOC Command Center", "security"),
        ]
        for node_id, label, kind in nodes:
            self.graph.add_node(node_id, label=label, kind=kind)
        edges = [
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
            self.graph.add_edge(source, target, label=label)

    def export(self) -> dict:
        return {
            "nodes": [{"id": n, **data} for n, data in self.graph.nodes(data=True)],
            "edges": [{"source": s, "target": t, **data} for s, t, data in self.graph.edges(data=True)],
            "simulated": True,
        }

    def simulate(self) -> dict:
        path = ["candidate-portal", "auth-db", "marking", "proctoring"]
        return {
            "path": path,
            "steps": [
                {"node": node, "order": idx + 1, "note": self.graph.nodes[node]["label"]}
                for idx, node in enumerate(path)
            ],
            "label": "SIMULATED digital twin walk-through; no live session is touched.",
        }

