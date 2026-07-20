# Security And Production Hardening

This repository is no longer only a hackathon MVP. It now includes the first production-readiness layer:

- Environment-driven backend settings in `app/config.py`.
- SQL persistence mirror via SQLAlchemy in `app/db.py`.
- Optional operator API key for high-impact routes.
- Ingest rate limiting.
- Dockerfiles and `docker-compose.yml` with Postgres.
- Pytest API smoke tests.
- `/ready` dependency readiness endpoint.
- `/audit/verify` hash-chain integrity endpoint.

## Required Before Real Deployment

- Replace demo passwords and frontend demo accounts with SSO/OIDC.
- Put the API behind TLS and an API gateway.
- Set `AEGIS_API_KEY` to a long random secret or replace it with OAuth2/JWT.
- Use Postgres, not the default SQLite development database.
- Configure WORM/object-lock storage for audit exports.
- Add SIEM, EDR, identity, cloud, firewall, DNS, proxy, and app-log connectors.
- Add analyst RBAC and approval workflows backed by persistent tickets.
- Move FastAPI startup hooks to lifespan handlers and add graceful shutdown health checks.
- Run red-team and tabletop exercises before enabling real containment actions.

## Safe Testing

Use `backend/tools/attack_simulator.py` for benign ATT&CK telemetry simulation. Do not use real exploit tooling against systems you do not own or have explicit authorization to test.
