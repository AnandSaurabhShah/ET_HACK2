from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app


def test_health_and_eval_report() -> None:
    with TestClient(app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["ok"] is True
        ready = client.get("/ready")
        assert ready.status_code == 200
        assert ready.json()["database"]["ok"] is True
        assert ready.json()["predictive_risk_model_fit"] is True
        assert "genai_attribution" in ready.json()

        report = client.get("/eval/report")
        assert report.status_code == 200
        body = report.json()
        assert body["detection_rate"] > 0
        assert body["mitre_technique_count"] >= 600


def test_ingest_safe_event() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/ingest/events",
            json={
                "user_id": "TEST-CAND-001",
                "role": "candidate",
                "device_id": "TEST-DEVICE",
                "segment": "candidate-portal",
                "ip": "127.0.0.1",
                "event_type": "login",
                "success": False,
                "latency_ms": 320,
                "bytes_out": 8,
                "metadata": {"test": True},
            },
        )
        assert response.status_code == 202
        assert "score" in response.json()


def test_core_read_endpoints() -> None:
    with TestClient(app) as client:
        assert client.get("/alerts?limit=2").status_code == 200
        assert client.get("/cve-queue").status_code == 200
        assert client.get("/twin/graph").status_code == 200
        assert client.get("/audit?limit=2").status_code == 200
        assert client.get("/audit/verify").status_code == 200
        coverage = client.get("/coverage/mitre")
        assert coverage.status_code == 200
        assert coverage.json()["summary"]["total"] >= 600
        assert coverage.json()["summary"]["active_live"] >= 6
        connectors = client.get("/integrations/connectors")
        assert connectors.status_code == 200
        assert len(connectors.json()["items"]) >= 5
        assert client.get("/demo/status").status_code == 200
        assert client.get("/demo/status").json()["enabled"] is False
        paused = client.post("/demo/pause")
        assert paused.status_code == 200
        assert paused.json()["paused"] is True
        resumed = client.post("/demo/resume")
        assert resumed.status_code == 200
        assert resumed.json()["paused"] is False


def test_perimeter_signature_blocks_follow_up_request() -> None:
    with TestClient(app) as client:
        ip = "198.51.100.210"
        first = client.get("/health?q=' OR '1'='1", headers={"X-Forwarded-For": ip})
        assert first.status_code == 403

        follow_up = client.get("/health", headers={"X-Forwarded-For": ip})
        assert follow_up.status_code == 403

        audit = client.get("/audit/verify")
        assert audit.status_code == 200
        assert audit.json()["ok"] is True

        alerts = client.get("/alerts?source=live_traffic&limit=1")
        assert alerts.status_code == 200
        alert = alerts.json()["items"][0]
        assert "model_scores" in alert["event"]["metadata"]
        assert "prediction" in alert["event"]["metadata"]

        timeline = client.get(f"/incidents/{alert['alert_id']}/timeline")
        assert timeline.status_code == 200
        assert len(timeline.json()["items"]) >= 3

        copilot = client.post("/copilot/ask", json={"alert_id": alert["alert_id"], "question": "Why was this blocked?"})
        assert copilot.status_code == 200
        assert "answer" in copilot.json()


def test_scanner_user_agent_alone_is_supporting_signal_only() -> None:
    with TestClient(app) as client:
        ip = "198.51.100.211"
        first = client.get("/health", headers={"X-Forwarded-For": ip, "User-Agent": "sqlmap/1.8"})
        assert first.status_code == 200

        follow_up = client.get("/health", headers={"X-Forwarded-For": ip})
        assert follow_up.status_code == 200


def test_localhost_block_does_not_break_soc_read_dashboard() -> None:
    with TestClient(app) as client:
        first = client.get("/health?q=' OR '1'='1")
        assert first.status_code == 403

        protected_follow_up = client.get("/health")
        assert protected_follow_up.status_code == 403

        assert client.get("/alerts?source=live_traffic&limit=5").status_code == 200
        assert client.get("/audit?limit=5").status_code == 200
        assert client.get("/ready").status_code == 200
        assert client.get("/coverage/mitre").status_code == 200
        assert client.get("/integrations/connectors").status_code == 200
