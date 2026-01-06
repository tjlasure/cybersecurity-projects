# password_manager/core.py

from datetime import datetime, timezone
from hashlib import sha256
from .utils import generate_salt, load_common_passwords
from .storage import load_users, save_user, load_login_attempts, save_login_attempts
from .audit import log_audit
import pwinput

# -----------------------
# Constants
# -----------------------
MAX_FAILED_ATTEMPTS = 3
LOCKOUT_DURATION = 5 * 60  # in seconds


# -----------------------
# Password utilities
# -----------------------
def hash_password(password, salt):
    """Return SHA-256 hash of password + salt."""
    return sha256((password + salt).encode()).hexdigest()


def check_password_strength(password, common):
    """
    Returns a tuple: (is_strong: bool, rules: dict)
    - common: list of common passwords loaded from file
    """
    p = password.lower()
    common_set = set(common)  # convert to set for fast lookup

    rules = {
        "length": len(password) >= 8,
        "uppercase": any(c.isupper() for c in password),
        "lowercase": any(c.islower() for c in password),
        "digit": any(c.isdigit() for c in password),
        "symbol": any(not c.isalnum() for c in password),
        "uncommon": not any(c in p for c in common_set),
    }
    return all(rules.values()), rules


def prompt_password(common_passwords):
    """Prompt user to enter and confirm password with masking."""
    while True:
        pwd = pwinput.pwinput(prompt="Password: ", mask="●")
        confirm = pwinput.pwinput(prompt="Confirm Password: ", mask="●")
        if pwd != confirm:
            print("Passwords do not match. Try again.")
            continue
        valid, rules = check_password_strength(pwd, common_passwords)
        if not valid:
            print("Password does not meet strength requirements:")
            for rule, passed in rules.items():
                if not passed:
                    print(f"- {rule}")
            continue
        return pwd


# -----------------------
# Login system
# -----------------------
def login():
    """Prompt user to login, enforce lockout, and log events."""
    users = load_users()
    attempts = load_login_attempts()

    username = input("Username: ").strip()
    if username not in users:
        print("User not found.")
        log_audit("login_failed_unknown", username=username)
        return None

    record = attempts.get(username, {"failed": 0, "last": None})
    if record["failed"] >= MAX_FAILED_ATTEMPTS and record["last"]:
        elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(record["last"])).total_seconds()
        if elapsed < LOCKOUT_DURATION:
            print("Account temporarily locked.")
            log_audit("login_blocked", username=username, role=users[username]["role"])
            return None
        else:
            record = {"failed": 0, "last": None}

    pwd = pwinput.pwinput(prompt="Password: ", mask="●")
    hashed = hash_password(pwd, users[username]["salt"])

    if hashed == users[username]["hash"]:
        # Successful login
        attempts[username] = {"failed": 0, "last": None}
        save_login_attempts(attempts)
        print(f"Login successful. Welcome {username}!")
        log_audit("login_success", username=username, role=users[username]["role"])
        return username, users[username]["role"]

    # Failed login
    record["failed"] += 1
    record["last"] = datetime.now(timezone.utc).isoformat()
    attempts[username] = record
    save_login_attempts(attempts)
    log_audit("login_failed", username=username, role=users[username]["role"], details=f"count={record['failed']}")
    print("Incorrect password.")
    return None
