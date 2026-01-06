# password_manager/admin.py

from password_manager.storage import load_login_attempts, save_login_attempts, load_users
from password_manager.audit import log_audit
from datetime import datetime, timezone

# -----------------------
# Unlock a locked user
# -----------------------
def unlock_account(admin_username, target_username):
    """
    Unlock a user account. Only admin users should call this.
    Returns True if successful, False otherwise.
    """
    users = load_users()
    if admin_username not in users or users[admin_username]["role"] != "admin":
        return False  # non-admin cannot unlock

    attempts = load_login_attempts()

    if target_username not in attempts:
        # If no record, nothing to unlock
        return False

    # Reset failed attempts and last attempt
    attempts[target_username] = {"failed": 0, "last": None}
    save_login_attempts(attempts)

    # Log audit event
    log_audit(
        event="account_unlocked",
        username=target_username,
        role="admin",
        details=f"unlocked_by={admin_username}"
    )

    return True


# -----------------------
# Admin interactive menu
# -----------------------
def admin_menu(admin_username):
    """Simple menu for admin actions."""
    while True:
        print("\n=== Admin Menu ===")
        print("1. Unlock user account")
        print("2. Exit admin menu")
        choice = input("Choice: ").strip()

        if choice == "1":
            target = input("Enter username to unlock: ").strip()
            success = unlock_account(admin_username, target)
            if success:
                print(f"User '{target}' unlocked successfully.")
            else:
                print(f"Failed to unlock '{target}'. Make sure username exists.")
        elif choice == "2":
            print("Exiting admin menu.")
            break
        else:
            print("Invalid choice. Enter 1 or 2.")
