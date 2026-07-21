from __future__ import annotations


def zero_day_prevention_strategy() -> dict:
    return {
        "name": "Zero-Day Exploit Prevention Strategy",
        "summary": (
            "Zero-day risk cannot be eliminated by signatures or patching alone, so Aegis-CNI treats it as "
            "unknown-exploit behaviour: reduce exposed attack surface, detect abnormal sequences, contain blast "
            "radius, and preserve evidence until vendor fixes are available."
        ),
        "lifecycle": [
            {
                "stage": "unknown_vulnerability",
                "defensive_goal": "Minimise reachable vulnerable code before disclosure.",
                "controls": [
                    "Keep internet-facing services behind WAF/reverse proxy controls with strict allowlists.",
                    "Segment exam, admin, identity, and management planes so one exploit cannot cross zones.",
                    "Remove unused services, plugins, protocol handlers, and appliance management exposure.",
                ],
            },
            {
                "stage": "exploitation",
                "defensive_goal": "Detect behaviour that looks wrong even when the CVE is unknown.",
                "controls": [
                    "Score rare endpoint sequences, SSRF-like callback attempts, command-shaped inputs, and sudden privilege changes.",
                    "Correlate request telemetry, identity failures, endpoint process activity, DNS, and outbound traffic.",
                    "Use GenAI attribution only for defensive explanation and next-stage prediction, not payload generation.",
                ],
            },
            {
                "stage": "attack_execution",
                "defensive_goal": "Break post-exploitation paths before data theft or service disruption.",
                "controls": [
                    "Auto-block high-confidence perimeter sources and require approval for high-blast-radius isolation.",
                    "Revoke suspicious sessions, rotate exposed credentials, and enforce MFA step-up for privileged roles.",
                    "Apply least privilege, application control, EDR tamper protection, and egress deny-by-default policies.",
                ],
            },
            {
                "stage": "disclosure_and_patch",
                "defensive_goal": "Move from compensating controls to verified remediation.",
                "controls": [
                    "Prioritise vendor hotfixes for exposed assets and confirm version drift has closed.",
                    "Search backward through audit, request, endpoint, and identity logs for indicators of compromise.",
                    "Document containment, verification, and residual risk in the hash-chained audit trail.",
                ],
            },
        ],
        "watch_signals": [
            "First-seen request routes, parameters, user agents, or headers against exposed services.",
            "SSRF-shaped access from edge appliances to internal metadata, admin, or identity endpoints.",
            "Unexpected child processes, service writes, driver loads, or privileged file operations from security tools.",
            "Privilege escalation immediately after a low-privilege login or web request.",
            "New outbound destinations, DNS bursts, archive creation, or staged data before exfiltration.",
            "Security-control disablement, update failures, tamper alerts, or logging gaps.",
        ],
        "mitre_focus": [
            "T1190 Exploit Public-Facing Application",
            "T1189 Drive-by Compromise",
            "T1059 Command and Scripting Interpreter",
            "T1068 Exploitation for Privilege Escalation",
            "T1562 Impair Defenses",
            "T1041 Exfiltration Over C2 Channel",
            "T1499 Endpoint Denial of Service",
        ],
        "example_incidents": [
            {
                "name": "Stuxnet",
                "lesson": "Assume chained unknown flaws can cross from IT into operational systems; isolate high-consequence environments.",
            },
            {
                "name": "Sony Pictures 2014",
                "lesson": "Pair endpoint detection with identity hardening, segmentation, and tested recovery for destructive intrusions.",
            },
            {
                "name": "Log4Shell",
                "lesson": "Maintain software bills of materials and virtual patching so vulnerable libraries can be found and shielded quickly.",
            },
            {
                "name": "SonicWall SMA1000 CVE-2026-15409/CVE-2026-15410",
                "lesson": "Treat exposed remote-access appliances as crown-jewel gateways: hotfix fast, restrict management access, and hunt for edge-to-internal pivots.",
            },
            {
                "name": "Microsoft Defender BlueHammer/RedSun/UnDefend reports",
                "lesson": "Security tools need the same hardening as business apps: tamper protection, rapid platform updates, least privilege, and independent telemetry.",
            },
        ],
        "aegis_mapping": [
            "Live middleware detects exploit-shaped requests and blocks high-confidence sources.",
            "Predictive risk model raises alerts from abnormal sequences, not only known CVE signatures.",
            "ATT&CK RAG maps unknown behaviour to likely techniques and mitigations.",
            "Ollama GenAI produces defensive attribution, next-stage prediction, and operator guidance.",
            "SOAR playbooks contain sources/sessions while preserving an auditable approval trail.",
        ],
    }
