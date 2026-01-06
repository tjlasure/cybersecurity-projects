import pytest
from password_manager.admin import unlock_account
from password_manager.storage import save_user, save_login_attempts, load_login_attempts, USERS_FILE, LOGIN_ATTEMPTS_FILE

def test_unlock_existing_user(tmp_path, monkeypatch):
    fake_users_file = tmp_path / "users.json"
    fake_login_file = tmp_path / "login_attempts.json"

    monkeypatch.setattr("password_manager.storage.USERS_FILE", fake_users_file)
    monkeypatch.setattr("password_manager.storage.LOGIN_ATTEMPTS_FILE", fake_login_file)

    # Create admin and locked user
    save_user("admin", "admin", "salt", "hash")
    save_login_attempts({"bob": {"failed": 3, "last": "2026-01-05T10:00:00"}})

    result = unlock_account("admin", "bob")
    assert result is True

    # Ensure failed attempts reset
    attempts = load_login_attempts()
    assert attempts["bob"]["failed"] == 0
    assert attempts["bob"]["last"] is None

def test_unlock_denied_for_non_admin(tmp_path, monkeypatch):
    fake_users_file = tmp_path / "users.json"
    fake_login_file = tmp_path / "login_attempts.json"

    monkeypatch.setattr("password_manager.storage.USERS_FILE", fake_users_file)
    monkeypatch.setattr("password_manager.storage.LOGIN_ATTEMPTS_FILE", fake_login_file)

    save_user("user1", "user", "salt", "hash")
    save_login_attempts({"bob": {"failed": 3, "last": "2026-01-05T10:00:00"}})

    result = unlock_account("user1", "bob")
    assert result is False
