from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.paths import CVE_FEED_PATH, DATA_DIR
from app.storage import read_json, write_json

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CACHE_META_PATH = DATA_DIR / "nvd_cache_meta.json"

FALLBACK_CVES = [
    {"cve": "CVE-2026-EXAM-0001", "asset_id": "auth-db", "cvss": 9.4, "exploitability": 0.92, "summary": "Weak session invalidation path in legacy auth middleware.", "related_techniques": ["T1078", "T1110"], "source": "static_fallback"},
    {"cve": "CVE-2026-EXAM-0002", "asset_id": "certificate-service", "cvss": 8.1, "exploitability": 0.88, "summary": "Certificate lookup endpoint lacks adaptive throttling.", "related_techniques": ["T1499"], "source": "static_fallback"},
    {"cve": "CVE-2026-EXAM-0003", "asset_id": "marking", "cvss": 8.8, "exploitability": 0.78, "summary": "Marking portal file export can over-share script bundles.", "related_techniques": ["T1041", "T1005"], "source": "static_fallback"},
    {"cve": "CVE-2026-EXAM-0004", "asset_id": "proctoring", "cvss": 7.2, "exploitability": 0.64, "summary": "Stale proctor device trust token permits lateral portal access.", "related_techniques": ["T1021", "T1078"], "source": "static_fallback"},
]

ASSET_QUERIES = {
    "auth-db": {"keyword": "postgresql authentication", "techniques": ["T1078", "T1110"]},
    "certificate-service": {"keyword": "nginx denial of service certificate", "techniques": ["T1499"]},
    "marking": {"keyword": "node.js file disclosure", "techniques": ["T1041", "T1005"]},
    "proctoring": {"keyword": "webrtc authentication bypass", "techniques": ["T1021", "T1078"]},
}


def _metric(cve: dict[str, Any]) -> tuple[float, str]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0].get("cvssData", {})
            return float(data.get("baseScore", 0)), data.get("baseSeverity", "UNKNOWN")
    return 0.0, "UNKNOWN"


def _summary(cve: dict[str, Any]) -> str:
    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            return item.get("value", "")[:260]
    return "No English NVD description available."


def _fetch_asset(asset_id: str, keyword: str, techniques: list[str], limit: int = 3) -> list[dict]:
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": str(limit),
    }
    url = f"{NVD_CVE_API}?{urllib.parse.urlencode(params)}"
    with urllib.request.urlopen(url, timeout=20) as response:
        payload = json.loads(response.read().decode("utf-8"))
    rows = []
    for item in payload.get("vulnerabilities", [])[:limit]:
        cve = item["cve"]
        score, severity = _metric(cve)
        rows.append(
            {
                "cve": cve["id"],
                "asset_id": asset_id,
                "cvss": score,
                "exploitability": min(1.0, max(0.2, score / 10)),
                "summary": _summary(cve),
                "related_techniques": techniques,
                "source": "nvd_live",
                "severity": severity,
                "published": cve.get("published"),
                "lastModified": cve.get("lastModified"),
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
            }
        )
    return rows


def refresh_nvd_cache(force: bool = False, max_age_hours: int = 12) -> list[dict]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    meta = read_json(NVD_CACHE_META_PATH, {})
    if not force and CVE_FEED_PATH.exists() and meta.get("source") == "nvd_live":
        fetched_at = datetime.fromisoformat(meta["fetched_at"])
        if datetime.now(timezone.utc) - fetched_at < timedelta(hours=max_age_hours):
            return read_json(CVE_FEED_PATH, [])

    try:
        rows: list[dict] = []
        for asset_id, config in ASSET_QUERIES.items():
            asset_rows = _fetch_asset(asset_id, config["keyword"], config["techniques"])
            if not asset_rows:
                asset_rows = [row for row in FALLBACK_CVES if row["asset_id"] == asset_id]
            rows.extend(asset_rows)
            time.sleep(0.7)  # Be gentle with public NVD rate limits without an API key.
        if not rows:
            raise RuntimeError("NVD returned no CVEs for configured asset queries")
        source = "nvd_live" if all(row.get("source") == "nvd_live" for row in rows) else "mixed_nvd_live_and_fallback"
        write_json(CVE_FEED_PATH, rows)
        write_json(NVD_CACHE_META_PATH, {"source": source, "fetched_at": datetime.now(timezone.utc).isoformat(), "count": len(rows)})
        return rows
    except Exception as exc:
        fallback = read_json(CVE_FEED_PATH, [])
        if fallback:
            for row in fallback:
                row.setdefault("source", "cached")
            write_json(NVD_CACHE_META_PATH, {"source": "cached", "fetched_at": datetime.now(timezone.utc).isoformat(), "error": str(exc), "count": len(fallback)})
            return fallback
        write_json(CVE_FEED_PATH, FALLBACK_CVES)
        write_json(NVD_CACHE_META_PATH, {"source": "static_fallback", "fetched_at": datetime.now(timezone.utc).isoformat(), "error": str(exc), "count": len(FALLBACK_CVES)})
        return FALLBACK_CVES
