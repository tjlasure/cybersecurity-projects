import json
from pathlib import Path
import pytest
from password_manager.storage import save_user, load_users, save_login_attempts, load_login_attempts, USERS_FILE, LOGIN_ATTEMPTS_FILE
from password_manager.core import hash_password, check_password_strength, load_common_passwords
from password_manager.audit import AUDIT_LOG_FILE

# -----------------------
# User storage tests
# -----------------------
def test_save_and_load_user(tmp_path, monkeypatch):
    fake_users_file = tmp_path / "users.json"
    fake_login_file = tmp_path / "login_attempts.json"

    monkeypatch.setattr("password_manager.storage.USERS_FILE", fake_users_file)
    monkeypatch.setattr("password_manager.storage.LOGIN_ATTEMPTS_FILE", fake_login_file)

    save_user("alice", "user", "salt123", "hashedpwd")
    users = load_users()
    assert "alice" in users
    assert users["alice"]["role"] == "user"
    assert users["alice"]["salt"] == "salt123"
    assert users["alice"]["hash"] == "hashedpwd"

# -----------------------
# Login attempts tests
# -----------------------
def test_save_and_load_login_attempts(tmp_path, monkeypatch):
    fake_users_file = tmp_path / "users.json"
    fake_login_file = tmp_path / "login_attempts.json"
    monkeypatch.setattr("password_manager.storage.USERS_FILE", fake_users_file)
    monkeypatch.setattr("password_manager.storage.LOGIN_ATTEMPTS_FILE", fake_login_file)

    attempts = {"bob": {"failed": 2, "last": "2026-01-05T10:00:00"}}
    save_login_attempts(attempts)
    loaded = load_login_attempts()
    assert loaded == attempts

# -----------------------
# Hashing tests
# -----------------------
def test_hash_password_consistency():
    pwd = "Password123!"
    salt = "abc"
    h1 = hash_password(pwd, salt)
    h2 = hash_password(pwd, salt)
    assert h1 == h2

def test_hash_password_uniqueness():
    h1 = hash_password("pwd1", "salt1")
    h2 = hash_password("pwd2", "salt1")
    assert h1 != h2

# -----------------------
# Password strength tests
# -----------------------
def test_password_strength_valid():
    common = ["password", "123456"]
    valid, rules = check_password_strength("Strong1!", common)
    assert valid

def test_password_strength_invalid():
    common = ["password", "123456"]
    valid, rules = check_password_strength("password", common)
    assert not valid
