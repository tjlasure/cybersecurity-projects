Cybersecurity Log Analysis Tool

    Overview

        This Python tool analyzes authentication and security logs to detect suspicious activity. It parses logs, aggregates failed login attempts per user/IP, generates CSV reports, prints
        human-readable summaries, and logs alerts for potentially malicious behavior. It supports configurable thresholds and time windows for detecting unusual activity.

    Features

        Parses log lines for timestamps, usernames, IP addresses, and actions.

        Detects suspicious actions (configurable in config.json).

        Aggregates failed attempts and flags entries exceeding a threshold.

        Generates CSV reports of suspicious activity.

        Prints a human-readable report to the console.

        Logs alerts for threshold violations within a configurable time window.

        Optional email notification for alerts (configurable, currently commented out).

    Getting Started
        Prerequisites
            Python 3.9+
        Libraries: argparse, json, csv, datetime, pathlib (all part of the standard library)

    Installation
        Clone this repository:
            git clone https://github.com/<your-username>/cybersecurity-projects.git
            cd cybersecurity-projects
        (Optional) Set up a virtual environment:
            python -m venv venv
            source venv/bin/activate   # Linux/macOS
            venv\Scripts\activate      # Windows
        Verify Python is installed:
            python --version

    Configuration
        The tool uses a config.json file to define thresholds, time windows, file paths, and suspicious actions. 
            Example:
                {
                "threshold": 3,
                "time_window_minutes": 10,
                "log_file": "logs/auth.log",
                "report_file": "logs/suspicious_report.csv",
                "analyzed_log_file": "logs/analyzed_log.txt",
                "suspicious_actions": ["login_failed", "unauthorized_access"]
                }

                    threshold: Number of failed attempts required to flag activity.
                    time_window_minutes: Time window to check for repeated failed attempts.
                    log_file: Path to the input log file.
                    report_file: Path to output CSV report.
                    analyzed_log_file: Path to append parsed log entries.
                    suspicious_actions: List of actions considered suspicious.
    
    Usage
        Run the tool from the command line:
            python log_analysis.py --logfile logs/auth.log --reportfile logs/suspicious_report.csv --threshold 3
                *** All command-line arguments are optional; defaults are taken from config.json. ***
    
    Output

        Console report: Summarizes suspicious activity per user/IP.

        CSV report: Stores entries exceeding the threshold with timestamps.

        Alerts log: Records alerts for activity exceeding thresholds within the time window.

        Analyzed log: Records every successfully parsed line.

        Malformed log: Records any lines that could not be parsed.

    Optional Features

        Email alerting: Configure SMTP settings in log_analysis.py (currently commented out).

    Acknowledgments
        This project was developed in Python with the support of AI-assisted code suggestions. All design decisions, configuration, debugging, and overall implementation were completed by the
        developer. AI was used as a productivity tool to help with boilerplate code and structuring, while all core functionality, logic, and testing were implemented manually.

    License
        This project is licensed under the MIT License.