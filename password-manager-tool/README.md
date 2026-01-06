Password Manager
    A command-line password manager with user roles, password strength enforcement, login lockouts, and audit logging.

Features
    Create users with roles (user or admin)
    Enforce strong passwords (length, uppercase, lowercase, digit, symbol, and uncommon passwords)
    Password input masked for security using pwinput
    Track login attempts and temporarily lock accounts after too many failed attempts
    Admin users can unlock locked accounts
    Audit logs of user creation, logins, and admin actions
    All data stored in JSON files under a data/ folder

Directory Structure
    password-manager-tool/
    │
    ├─ data/                  # Stores users and login attempts
    │  ├─ users.json
    │  └─ login_attempts.json
    │
    ├─ logs/                  # Stores audit logs
    │  └─ audit.log.jsonl
    │
    ├─ password_manager/
    │  ├─ __init__.py
    │  ├─ core.py
    │  ├─ storage.py
    │  ├─ audit.py
    │  ├─ admin.py
    │  └─ utils.py
    │
    ├─ tests/                 # Unit tests
    ├─ requirements.txt       # Python dependencies
    └─ main.py                # Main interactive menu

Installation
    Clone the repository:
        git clone <repo-url>
        cd password-manager-tool
    Create a Python virtual environment:
        python3 -m venv venv
    Activate the virtual environment:
        # macOS/Linux
            source venv/bin/activate
        # Windows (PowerShell)
            venv\Scripts\Activate.ps1
    Install dependencies:
        pip install -r requirements.txt

Running the Password Manager
    Run the main menu:
        python main.py

You will see a menu with options:
    Create user – enter a username, role (user or admin), and a strong password.
    Login – enter your username and password. Admin users will have access to the admin menu.
    Exit – close the program.
    Passwords are masked with dots when typing, and you must confirm the password during creation.

Testing
    Run unit tests with pytest:
        pytest -v
    *All tests should pass if the environment is correctly set up.

Notes
    Data persistence: All users and login attempts are stored in JSON under data/. Audit logs are in data/audit.log.jsonl.
    Password masking: Uses the pwinput library, which should be installed in your environment.
    Password strength: Uses a list of common passwords to prevent weak choices. This can be edited to user's preference.

Dependencies
    Python 3.13+
    pwinput (for masked password input)
    Standard Python libraries: json, hashlib, datetime, pathlib

Acknowledgments
    This project was developed in Python with the support of AI-assisted code suggestions. All design decisions, configuration, debugging, and overall implementation were completed by the developer. AI was used as a productivity tool to help with boilerplate code and structuring, while all core functionality, logic, and testing were implemented manually.

License
    This project is licensed under the MIT License.