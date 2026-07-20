from __future__ import annotations

from typing import TypedDict

try:
    from langgraph.graph import END, StateGraph
except Exception:  # pragma: no cover - deterministic API still runs without graph execution.
    END = None
    StateGraph = None


class AegisState(TypedDict, total=False):
    event_id: str
    baseline_ready: bool
    anomaly_scored: bool
    attributed: bool
    playbook_ready: bool
    cve_ranked: bool
    graph_updated: bool


def build_agent_graph():
    """LangGraph artifact showing the five-agent order used by the API pipeline."""
    if StateGraph is None:
        return None
    graph = StateGraph(AegisState)
    graph.add_node("baseline_agent", lambda state: {**state, "baseline_ready": True})
    graph.add_node("anomaly_agent", lambda state: {**state, "anomaly_scored": True})
    graph.add_node("attribution_agent", lambda state: {**state, "attributed": True})
    graph.add_node("orchestrator_agent", lambda state: {**state, "playbook_ready": True})
    graph.add_node("cve_agent", lambda state: {**state, "cve_ranked": True})
    graph.add_node("graph_agent", lambda state: {**state, "graph_updated": True})
    graph.set_entry_point("baseline_agent")
    graph.add_edge("baseline_agent", "anomaly_agent")
    graph.add_edge("anomaly_agent", "attribution_agent")
    graph.add_edge("attribution_agent", "orchestrator_agent")
    graph.add_edge("orchestrator_agent", "cve_agent")
    graph.add_edge("cve_agent", "graph_agent")
    graph.add_edge("graph_agent", END)
    return graph.compile()

