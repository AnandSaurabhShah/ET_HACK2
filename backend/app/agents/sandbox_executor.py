from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from app.paths import DATA_DIR

SANDBOX_DIR = DATA_DIR / "soar_sandbox"
NETWORK_NAME = "aegis-cni-sandbox"


def _run(args: list[str], timeout: int = 20) -> tuple[bool, str]:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        output = (proc.stdout + proc.stderr).strip()
        return proc.returncode == 0, output
    except Exception as exc:
        return False, str(exc)


def _write_evidence(name: str, payload: dict) -> str:
    SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
    path = SANDBOX_DIR / name
    existing = []
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8"))
    existing.append({**payload, "timestamp": datetime.now(timezone.utc).isoformat()})
    path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    return str(path)


class SandboxExecutor:
    """Executes playbook steps against a throwaway local sandbox.

    Docker-backed actions are real and verifiable when Docker is installed. The
    local evidence files are still written for auditability and demo replay.
    """

    def docker_available(self) -> bool:
        return shutil.which("docker") is not None

    def _container_name(self, device_id: str) -> str:
        safe = "".join(ch.lower() if ch.isalnum() else "-" for ch in device_id)[:42]
        return f"aegis-{safe}"

    def _ensure_container(self, device_id: str) -> tuple[bool, str, str]:
        if not self.docker_available():
            return False, "", "Docker is not installed or not on PATH"
        _run(["docker", "network", "create", NETWORK_NAME])
        name = self._container_name(device_id)
        ok, inspect = _run(["docker", "inspect", name], timeout=10)
        if not ok:
            ok, output = _run(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    name,
                    "--cap-add",
                    "NET_ADMIN",
                    "--network",
                    NETWORK_NAME,
                    "alpine:3.20",
                    "sleep",
                    "3600",
                ],
                timeout=45,
            )
            if not ok:
                return False, name, output
        return True, name, inspect

    def execute(self, action: str, *, alert_id: str, device_id: str, ip: str, user_id: str) -> dict:
        if action == "snapshot_state":
            evidence = _write_evidence(
                "snapshots.json",
                {"alert_id": alert_id, "device_id": device_id, "ip": ip, "user_id": user_id},
            )
            return {"verified": True, "details": f"Snapshot evidence written to {evidence}"}

        if action.startswith("revoke_session:"):
            evidence = _write_evidence(
                "revoked_sessions.json",
                {"alert_id": alert_id, "user_id": action.split(":", 1)[1]},
            )
            return {"verified": True, "details": f"Revocation evidence written to {evidence}"}

        if action.startswith("block_ip:"):
            target_ip = action.split(":", 1)[1]
            ok, container, message = self._ensure_container(device_id)
            if not ok:
                evidence = _write_evidence("blocked_ips_fallback.json", {"alert_id": alert_id, "ip": target_ip, "reason": message})
                return {"verified": False, "details": f"Docker unavailable; fallback evidence written to {evidence}: {message}"}
            ok, output = _run(["docker", "exec", container, "sh", "-c", f"ip route add blackhole {target_ip} 2>/dev/null || true; ip route show | grep '{target_ip}'"])
            verified = ok and target_ip in output
            evidence = _write_evidence("blocked_ips.json", {"alert_id": alert_id, "ip": target_ip, "container": container, "verified": verified, "output": output})
            return {"verified": verified, "details": f"Docker sandbox route check stored in {evidence}: {output or 'no route output'}"}

        if action.startswith("isolate_endpoint:"):
            target_device = action.split(":", 1)[1]
            ok, container, message = self._ensure_container(target_device)
            if not ok:
                evidence = _write_evidence("isolated_endpoints_fallback.json", {"alert_id": alert_id, "device_id": target_device, "reason": message})
                return {"verified": False, "details": f"Docker unavailable; fallback evidence written to {evidence}: {message}"}
            _run(["docker", "network", "disconnect", "-f", NETWORK_NAME, container])
            ok, output = _run(["docker", "inspect", "-f", "{{json .NetworkSettings.Networks}}", container])
            verified = ok and NETWORK_NAME not in output
            evidence = _write_evidence("isolated_endpoints.json", {"alert_id": alert_id, "device_id": target_device, "container": container, "verified": verified, "output": output})
            return {"verified": verified, "details": f"Docker network isolation evidence stored in {evidence}"}

        evidence = _write_evidence("unknown_actions.json", {"alert_id": alert_id, "action": action})
        return {"verified": False, "details": f"Unknown action recorded in {evidence}"}

