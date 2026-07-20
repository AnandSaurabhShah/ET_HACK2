# Industry-Scale Roadmap

## Phase 1: Production Foundation

Status: started in this repo.

- SQL persistence mirror.
- Configurable runtime settings.
- API-key gate for operator actions.
- Ingest rate limiting.
- Docker deployment.
- API smoke tests.

Remaining:

- Alembic migrations.
- Full repository pattern replacing all JSON reads.
- Persistent playbook run store.
- Analyst identity and RBAC.
- Observability with OpenTelemetry, Prometheus, and structured logs.

## Phase 2: Real Telemetry

- SIEM connector: Splunk, Sentinel, Elastic, QRadar.
- Identity connector: Okta, Entra ID, LDAP.
- EDR connector: Defender, CrowdStrike, SentinelOne.
- Network connector: firewall, proxy, DNS, NetFlow.
- App connector: auth/session/certificate/exam logs.
- Streaming backbone: Kafka, Redpanda, Kinesis, or Pulsar.

## Phase 3: Detection Platform

- Online feature store.
- Per-entity baselines.
- Sequence and graph models.
- Model registry and drift monitoring.
- Analyst feedback loop.
- Evaluation on production-labelled incidents.

## Phase 4: Production SOAR

- Connector-specific containment adapters.
- Dry-run mode.
- Rollback plans.
- Change-window controls.
- Approval policy by asset criticality and blast radius.
- Ticket linkage with Jira, ServiceNow, or equivalent.

## Phase 5: Enterprise Platform

- Multi-tenancy.
- Tenant-specific encryption keys.
- Data residency controls.
- SSO/SAML/OIDC and SCIM.
- Compliance mapping: ISO 27001, SOC 2, NIST CSF, CERT-In, DPDP.
- HA/DR and SLOs for detection and response latency.

