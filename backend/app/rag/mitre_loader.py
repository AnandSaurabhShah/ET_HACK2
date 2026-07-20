from __future__ import annotations

import json
import urllib.request
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from app.models.schemas import MitreTechnique
from app.paths import MITRE_SOURCE_PATH, MITRE_TECHNIQUES_PATH, ensure_dirs
from app.storage import read_json, write_json

MITRE_ENTERPRISE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)


FALLBACK_TECHNIQUES = [
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactics": ["defense-evasion", "persistence", "privilege-escalation", "initial-access"],
        "description": "Adversaries may obtain and abuse credentials of existing accounts.",
        "mitigations": ["M1032 Multi-factor Authentication", "M1027 Password Policies"],
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactics": ["credential-access"],
        "description": "Adversaries may use brute force techniques to gain access to accounts.",
        "mitigations": ["M1032 Multi-factor Authentication", "M1036 Account Use Policies"],
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    {
        "id": "T1021",
        "name": "Remote Services",
        "tactics": ["lateral-movement"],
        "description": "Adversaries may use valid accounts to log into a service remotely.",
        "mitigations": ["M1035 Limit Access to Resource Over Network", "M1030 Network Segmentation"],
        "url": "https://attack.mitre.org/techniques/T1021/",
    },
    {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactics": ["exfiltration"],
        "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
        "mitigations": ["M1031 Network Intrusion Prevention", "M1037 Filter Network Traffic"],
        "url": "https://attack.mitre.org/techniques/T1041/",
    },
    {
        "id": "T1499",
        "name": "Endpoint Denial of Service",
        "tactics": ["impact"],
        "description": "Adversaries may perform Endpoint Denial of Service attacks to degrade availability.",
        "mitigations": ["M1037 Filter Network Traffic", "M1030 Network Segmentation"],
        "url": "https://attack.mitre.org/techniques/T1499/",
    },
    {
        "id": "T1005",
        "name": "Data from Local System",
        "tactics": ["collection"],
        "description": "Adversaries may search local system sources for files of interest.",
        "mitigations": ["M1057 Data Loss Prevention", "M1041 Encrypt Sensitive Information"],
        "url": "https://attack.mitre.org/techniques/T1005/",
    },
]


def _external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def _url(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("url"):
            return ref["url"]
    return ""


def download_mitre_source() -> None:
    ensure_dirs()
    if MITRE_SOURCE_PATH.exists():
        return
    try:
        with urllib.request.urlopen(MITRE_ENTERPRISE_STIX_URL, timeout=45) as response:
            MITRE_SOURCE_PATH.write_bytes(response.read())
    except Exception:
        write_json(MITRE_TECHNIQUES_PATH, FALLBACK_TECHNIQUES)


def build_mitre_corpus() -> list[MitreTechnique]:
    ensure_dirs()
    if MITRE_TECHNIQUES_PATH.exists():
        return [MitreTechnique(**row) for row in read_json(MITRE_TECHNIQUES_PATH, FALLBACK_TECHNIQUES)]

    download_mitre_source()
    if not MITRE_SOURCE_PATH.exists():
        write_json(MITRE_TECHNIQUES_PATH, FALLBACK_TECHNIQUES)
        return [MitreTechnique(**row) for row in FALLBACK_TECHNIQUES]

    bundle = json.loads(MITRE_SOURCE_PATH.read_text(encoding="utf-8"))
    objects = bundle.get("objects", [])
    mitigations_by_stix = {
        obj["id"]: f"{_external_id(obj) or obj['id']} {obj.get('name', '')}"
        for obj in objects
        if obj.get("type") == "course-of-action" and not obj.get("revoked") and not obj.get("x_mitre_deprecated")
    }
    mitigation_edges: dict[str, list[str]] = {}
    for obj in objects:
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "mitigates":
            mitigation = mitigations_by_stix.get(obj.get("source_ref"))
            if mitigation:
                mitigation_edges.setdefault(obj.get("target_ref", ""), []).append(mitigation)

    techniques: list[dict] = []
    for obj in objects:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tid = _external_id(obj)
        if not tid or not tid.startswith("T"):
            continue
        tactics = [phase.get("phase_name", "") for phase in obj.get("kill_chain_phases", [])]
        techniques.append(
            {
                "id": tid,
                "name": obj.get("name", ""),
                "tactics": tactics,
                "description": obj.get("description", "")[:1400],
                "mitigations": sorted(set(mitigation_edges.get(obj["id"], []))),
                "url": _url(obj),
            }
        )
    techniques.sort(key=lambda row: row["id"])
    write_json(MITRE_TECHNIQUES_PATH, techniques or FALLBACK_TECHNIQUES)
    return [MitreTechnique(**row) for row in (techniques or FALLBACK_TECHNIQUES)]


class TechniqueRetriever:
    def __init__(self, techniques: list[MitreTechnique] | None = None) -> None:
        self.techniques = techniques or build_mitre_corpus()
        self.vectorizer = TfidfVectorizer(stop_words="english", max_features=5000)
        self.docs = [
            f"{t.id} {t.name} {' '.join(t.tactics)} {t.description} {' '.join(t.mitigations)}"
            for t in self.techniques
        ]
        self.matrix = self.vectorizer.fit_transform(self.docs)
        self.by_id = {t.id: t for t in self.techniques}

    def get(self, technique_id: str) -> MitreTechnique | None:
        return self.by_id.get(technique_id)

    def query(self, text: str, limit: int = 5) -> list[MitreTechnique]:
        q = self.vectorizer.transform([text])
        scores = cosine_similarity(q, self.matrix).ravel()
        ranked = scores.argsort()[::-1][:limit]
        return [self.techniques[i] for i in ranked if scores[i] > 0]

