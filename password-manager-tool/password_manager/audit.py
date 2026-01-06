# password_manager/audit.py

import json
from datetime import datetime, timezone
from pathlib import Path

# -----------------------
# Log file path
# -----------------------
AUDIT_LOG_FILE = Path("./data/audit.log.jsonl")


def log_audit(event, username=None, role=None, details=None):
    """
    Append an audit event to a JSONL log file.
    Each line is a separate JSON object.
    """
    AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "event": event,
        "username": username,
        "role": role,
        "details": details,
    }
    with AUDIT_LOG_FILE.open("a") as f:
        f.write(json.dumps(record) + "\n")
