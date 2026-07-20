# Safe ATT&CK Simulator

This folder intentionally does **not** contain exploit code, malware code, credential theft, persistence scripts, destructive payloads, or denial-of-service tooling.

Use `attack_simulator.py` to generate safe, labelled telemetry for any MITRE Enterprise ATT&CK technique in the local corpus. The backend then scores it, maps it to ATT&CK, raises alerts, runs playbooks, and writes audit entries.

List techniques:

```bash
cd backend
python tools/attack_simulator.py --list --limit 30
python tools/attack_simulator.py --list --tactic credential-access
```

Run one selected technique:

```bash
python tools/attack_simulator.py --technique T1110 --count 8
python tools/attack_simulator.py --technique T1499 --count 8
python tools/attack_simulator.py --technique T1041 --count 8
```

Then open the SOC UI at `http://127.0.0.1:5173`, sign in with `SOC-AEGIS-001 / security`, and watch the anomaly feed, attribution panel, playbook console, and audit table.

