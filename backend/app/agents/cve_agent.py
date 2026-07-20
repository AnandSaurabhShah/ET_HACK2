from __future__ import annotations

from app.paths import ASSET_INVENTORY_PATH, CVE_FEED_PATH
from app.storage import read_json


class CveAgent:
    def rank(self, observed_techniques: list[str]) -> list[dict]:
        assets = read_json(ASSET_INVENTORY_PATH, [])
        cves = read_json(CVE_FEED_PATH, [])
        observed = set(observed_techniques)
        asset_by_id = {asset["asset_id"]: asset for asset in assets}
        ranked = []
        for cve in cves:
            asset = asset_by_id.get(cve["asset_id"], {})
            ttp_overlap = len(observed.intersection(cve.get("related_techniques", [])))
            criticality = asset.get("criticality", 1)
            score = cve["cvss"] * 8 + cve["exploitability"] * 12 + ttp_overlap * 15 + criticality * 7
            ranked.append({**cve, "asset": asset, "risk_score": round(score, 1), "ttp_overlap": ttp_overlap})
        return sorted(ranked, key=lambda row: row["risk_score"], reverse=True)

