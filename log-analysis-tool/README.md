# Cybersecurity Log Analysis Tool

A Python-based log analysis tool designed to detect suspicious authentication activity such as repeated failed login attempts.
This project demonstrates foundational cybersecurity concepts including log parsing, anomaly detection, and basic alerting.

---

## 📌 Features

* Parses authentication log files
* Detects suspicious login behavior based on configurable thresholds
* Supports time-based analysis (e.g., X failed attempts within Y minutes)
* Outputs:

  * Human-readable terminal report
  * CSV report for further analysis
  * Log files for analyzed and malformed entries
* Optional email alerting (currently commented out for safety)

---

## 📁 Project Structure

```
cybersecurity-projects/
│
├── logs/
│   ├── analyzed_log.txt        # Parsed and validated log entries
│   ├── alerts.txt              # Alert output
│   └── malformed_lines.txt     # Invalid or malformed log lines
│
├── config.json                 # Configuration settings
├── main.py                     # Main application script
├── README.md                   # Project documentation
├── LICENSE                     # MIT License
└── .gitignore                  # Git ignore rules
```

---

## ⚙️ Configuration (`config.json`)

Example configuration:

```json
{
  "threshold": 3,
  "time_window_minutes": 10,
  "log_file": "logs/auth.log",
  "report_file": "logs/suspicious_report.csv",
  "analyzed_log_file": "logs/analyzed_log.txt",
  "suspicious_actions": ["login_failed", "unauthorized_access"]
}
```

### Configuration Options

* **threshold** – Number of failed attempts before triggering an alert
* **time_window_minutes** – Time window for detecting repeated failures
* **log_file** – Input log file to analyze
* **report_file** – Output CSV report path
* **analyzed_log_file** – Parsed log output
* **suspicious_actions** – Actions considered suspicious

---

## ▶️ How to Run

From the project root:

```bash
python main.py
```

Optional CLI arguments:

```bash
python main.py --logfile logs/auth.log --threshold 5
```

---

## 📊 Output

* Console summary of suspicious activity
* CSV report of flagged users/IPs
* Logged alerts and malformed entries in the `logs/` directory

---

## 🛡️ Security Notes

* Email alerting is intentionally disabled by default.
* No credentials or secrets are stored in this repository.
* Designed for learning and demonstration purposes.

---

## 📘 What This Project Demonstrates

* Python scripting
* Log parsing and validation
* Time-based event correlation
* CLI argument handling
* File I/O and error handling
* Clean project structure and documentation

---

## 📄 License

This project is licensed under the MIT License.
See the `LICENSE` file for details.

---

## ✍️ Author

Created by **[Your Name]**
Built as part of a cybersecurity learning journey.

---

## 🤖 AI Assistance Disclosure

This project was developed in Python with the support of AI-assisted code suggestions. 
All design decisions, configuration, debugging, and overall implementation were completed by the developer.
AI was used as a productivity tool to help with boilerplate code and structuring, 
while all core functionality, logic, and testing were implemented manually.
