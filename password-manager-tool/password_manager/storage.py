# password_manager/storage.py

import json
from pathlib import Path
from datetime import datetime, timezone
from .audit import log_audit

# -----------------------
# File paths
# -----------------------
DATA_DIR = Path("./data")
DATA_DIR.mkdir(exist_ok=True)

USERS_FILE = DATA_DIR / "users.json"
LOGIN_ATTEMPTS_FILE = DATA_DIR / "login_attempts.json"


# -----------------------
# Users
# -----------------------
def load_users():
    """Load all users from JSON file. Returns dict of username -> user info."""
    if not USERS_FILE.exists():
        return {}
    with USERS_FILE.open("r") as f:
        return json.load(f)


def save_user(username, role, salt, hashed):
    """Add or update a user in JSON storage."""
    users = load_users()
    users[username] = {
        "role": role,
        "salt": salt,
        "hash": hashed,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    with USERS_FILE.open("w") as f:
        json.dump(users, f, indent=4)
    log_audit("user_created", username=username, role=role)


# -----------------------
# Login attempts
# -----------------------
def load_login_attempts():
    """Load login attempts from JSON file."""
    if not LOGIN_ATTEMPTS_FILE.exists():
        return {}
    with LOGIN_ATTEMPTS_FILE.open("r") as f:
        return json.load(f)


def save_login_attempts(attempts):
    """Save login attempts to JSON file."""
    with LOGIN_ATTEMPTS_FILE.open("w") as f:
        json.dump(attempts, f, indent=4)
