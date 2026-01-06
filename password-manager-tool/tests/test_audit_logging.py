import json
from pathlib import Path
from password_manager.admin import unlock_account
from password_manager.storage import save_login_attempts, save_user, USERS_FILE, LOGIN_ATTEMPTS_FILE
from password_manager.audit import AUDIT_LOG_FILE

def test_admin_unlock_writes_audit_log(tmp_path, monkeypatch):
    fake_audit_file = tmp_path / "audit.log.jsonl"
    fake_users_file = tmp_path / "users.json"
    fake_login_file = tmp_path / "login_attempts.json"

    monkeypatch.setattr("password_manager.audit.AUDIT_LOG_FILE", fake_audit_file)
    monkeypatch.setattr("password_manager.storage.USERS_FILE", fake_users_file)
    monkeypatch.setattr("password_manager.storage.LOGIN_ATTEMPTS_FILE", fake_login_file)

    save_user("admin_user", "admin", "salt", "hashed")
    save_login_attempts({"bob": {"failed": 3, "last": "2026-01-05T10:00:00"}})

    result = unlock_account("admin_user", "bob")
    assert result is True

    with open(fake_audit_file) as f:
        lines = f.readlines()

    # Two events: user_created + account_unlocked
    assert len(lines) == 2

    entry = json.loads(lines[-1])
    assert entry["event"] == "account_unlocked"
    assert entry["username"] == "bob"
    assert entry["role"] == "admin"
    assert "admin_user" in entry["details"]
