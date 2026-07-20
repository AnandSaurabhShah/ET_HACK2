from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
BACKEND_DIR = APP_DIR.parent
ROOT_DIR = BACKEND_DIR.parent
DATA_DIR = APP_DIR / "data"
RAG_DIR = APP_DIR / "rag"
FIXTURES_DIR = RAG_DIR / "fixtures"
AUDIT_DIR = APP_DIR / "audit"

EVENTS_PATH = DATA_DIR / "events.jsonl"
ALERTS_PATH = DATA_DIR / "alerts.json"
EVAL_REPORT_PATH = DATA_DIR / "eval_report.json"
CVE_FEED_PATH = DATA_DIR / "cve_feed.json"
ASSET_INVENTORY_PATH = DATA_DIR / "asset_inventory.json"
MITRE_TECHNIQUES_PATH = FIXTURES_DIR / "mitre_enterprise_techniques.json"
MITRE_SOURCE_PATH = FIXTURES_DIR / "mitre_enterprise_source.json"
AUDIT_LOG_PATH = AUDIT_DIR / "audit_log.jsonl"


def ensure_dirs() -> None:
    for path in (DATA_DIR, FIXTURES_DIR, AUDIT_DIR):
        path.mkdir(parents=True, exist_ok=True)

