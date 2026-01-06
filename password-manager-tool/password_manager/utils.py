# password_manager/utils.py

import secrets
from pathlib import Path

DATA_DIR = Path("./data")
COMMON_PASSWORDS_FILE = DATA_DIR / "common_passwords.txt"

def generate_salt(length=16):
    """Generate a cryptographically secure random salt."""
    return secrets.token_hex(length)

def load_common_passwords():
    """Load common passwords from file and return as a list of strings."""
    if not COMMON_PASSWORDS_FILE.exists():
        return []
    with COMMON_PASSWORDS_FILE.open("r") as f:
        return [line.strip() for line in f]