from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ConnectorCapability:
    name: str
    category: str
    status: str
    production_target: str
    implemented_interface: list[str] = field(default_factory=list)
    required_for: list[str] = field(default_factory=list)


CONNECTORS = [
    ConnectorCapability(
        name="SIEMConnector",
        category="telemetry",
        status="interface_ready",
        production_target="Splunk, Microsoft Sentinel, Elastic, Chronicle, Kafka/OpenTelemetry",
        implemented_interface=["normalize_event", "stream_events", "acknowledge_offset"],
        required_for=["multi-source IT log correlation", "enterprise detection scale", "retention/search"],
    ),
    ConnectorCapability(
        name="EDRConnector",
        category="containment",
        status="interface_ready",
        production_target="Microsoft Defender, CrowdStrike, SentinelOne, VMware Carbon Black",
        implemented_interface=["isolate_endpoint", "collect_triage", "release_endpoint"],
        required_for=["process injection detection", "credential dumping detection", "real endpoint isolation"],
    ),
    ConnectorCapability(
        name="IAMConnector",
        category="identity",
        status="interface_ready",
        production_target="Entra ID, Okta, Keycloak, LDAP/Active Directory",
        implemented_interface=["revoke_session", "disable_account", "require_step_up_mfa"],
        required_for=["valid-account abuse", "brute-force containment", "privilege escalation response"],
    ),
    ConnectorCapability(
        name="FirewallConnector",
        category="network",
        status="interface_ready",
        production_target="WAF, API Gateway, NGFW, cloud security groups, load balancer ACLs",
        implemented_interface=["block_ip", "rate_limit_ip", "release_ip"],
        required_for=["network-wide blocking", "C2 egress control", "scan suppression"],
    ),
    ConnectorCapability(
        name="CloudAuditConnector",
        category="cloud",
        status="interface_ready",
        production_target="AWS CloudTrail, Azure Activity Logs, GCP Audit Logs, SaaS audit APIs",
        implemented_interface=["ingest_audit_event", "map_principal", "resolve_asset"],
        required_for=["cloud control-plane abuse", "SaaS persistence", "tenant policy tampering"],
    ),
    ConnectorCapability(
        name="OTSensorConnector",
        category="ot",
        status="interface_ready",
        production_target="Zeek, Suricata, industrial protocol taps, historian logs, PLC/SCADA telemetry",
        implemented_interface=["ingest_flow", "map_process_asset", "flag_protocol_anomaly"],
        required_for=["IT/OT weak-signal correlation", "industrial protocol anomaly detection", "safety-impact modelling"],
    ),
]


def connector_catalog() -> list[dict]:
    return [
        {
            "name": item.name,
            "category": item.category,
            "status": item.status,
            "production_target": item.production_target,
            "implemented_interface": item.implemented_interface,
            "required_for": item.required_for,
        }
        for item in CONNECTORS
    ]
