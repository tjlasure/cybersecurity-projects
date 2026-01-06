# password_manager/main.py

from password_manager.core import prompt_password, hash_password, generate_salt, load_common_passwords, login
from password_manager.storage import save_user, load_users
from password_manager.audit import log_audit
from password_manager.admin import admin_menu

# -----------------------
# Main interactive menu
# -----------------------
def main():
    # Load common passwords for strength checking
    common_passwords = load_common_passwords()

    while True:
        print("\n=== Password Manager ===")
        print("1. Create user")
        print("2. Login")
        print("3. Exit")
        choice = input("Choice: ").strip()

        # -----------------------
        # Create a new user
        # -----------------------
        if choice == "1":
            username = input("Username: ").strip()
            role = input("Role (user/admin): ").strip().lower()
            if role not in {"user", "admin"}:
                print("Invalid role. Must be 'user' or 'admin'.")
                continue

            # Check if username already exists
            existing_users = load_users()
            if username in existing_users:
                print(f"Username '{username}' already exists. Choose a different username.")
                continue

            pwd = prompt_password(common_passwords)
            salt = generate_salt()
            hashed = hash_password(pwd, salt)
            save_user(username, role, salt, hashed)
            print(f"User '{username}' created successfully.")

        # -----------------------
        # User login
        # -----------------------
        elif choice == "2":
            result = login()
            if result:
                username, role = result
                print(f"Welcome, {username}!")
                if role == "admin":
                    admin_menu(username)
                else:
                    print("Logged in as regular user.")
                break  # Exit menu after login

        # -----------------------
        # Exit program
        # -----------------------
        elif choice == "3":
            print("Exiting password manager.")
            break

        else:
            print("Invalid choice. Enter 1, 2, or 3.")


# -----------------------
# Entry point
# -----------------------
if __name__ == "__main__":
    main()
