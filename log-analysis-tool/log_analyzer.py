import argparse                            # handle CLI arguments
import json                                # load config file
import csv                                 # write CSV report
from datetime import datetime, timedelta   # handle timestamps
from pathlib import Path                   # handle file paths
# import smtplib                           # Uncomment if email alerts are needed
# from email.message import EmailMessage   # Uncomment if email alerts are needed


# === LOAD CONFIGURATION ===
with open("config.json", "r") as f:
    config = json.load(f)

# === CONSTANTS / CONFIG VALUES ===
THRESHOLD = config["threshold"]  # failed login attempt threshold
TIME_WINDOW_MINUTES = config.get("time_window_minutes", 10)  # time window in minutes
LOG_FILE = Path(config["log_file"])  # log file to analyze
REPORT_FILE = Path(config["report_file"])  # output CSV report
ANALYZED_LOG_FILE = Path(config["analyzed_log_file"])  # store parsed log lines
SUSPICIOUS_ACTIONS = config["suspicious_actions"]  # list of suspicious actions
ALERT_LOG_FILE = Path("logs/alerts.txt")  # alert log file
MALFORMED_LOG_FILE = Path("logs/malformed_lines.txt")  # malformed log lines

# Ensure directories exist for all paths
for path in [LOG_FILE, REPORT_FILE, ANALYZED_LOG_FILE, ALERT_LOG_FILE, MALFORMED_LOG_FILE]:
    path.parent.mkdir(parents=True, exist_ok=True)


# === ARGPARSE SETUP ===
def existing_file(path_str):
    """Ensure CLI-provided file exists."""
    p = Path(path_str)
    if not p.exists():
        raise argparse.ArgumentTypeError(f"File does not exist: {path_str}")
    return p

parser = argparse.ArgumentParser(description="Log Analysis Tool")
parser.add_argument("--logfile", type=existing_file, default=LOG_FILE, help="Path to the log file to analyze")
parser.add_argument("--reportfile", type=Path, default=REPORT_FILE, help="Path to the output CSV report")
parser.add_argument("--threshold", type=int, default=THRESHOLD, help="Failed attempts threshold")
args = parser.parse_args()

LOG_FILE = args.logfile
REPORT_FILE = args.reportfile
THRESHOLD = args.threshold


# === LOG ANALYSIS FUNCTIONS ===
def parse_log_line(line):
    """Parse a single log line and return (timestamp, user, ip, action) or None for malformed lines."""
    line = line.strip()
    try:
        parts = line.split()
        timestamp_str = parts[0] + " " + parts[1]
        user = parts[2].split("=")[1]
        ip = parts[3].split("=")[1]
        action = parts[4].split("=")[1]

        # Validate timestamp format
        datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

        # Append analyzed line
        with ANALYZED_LOG_FILE.open("a") as f:
            f.write(f"[{timestamp_str}] User={user} IP={ip} Action={action}\n")

        return timestamp_str, user, ip, action

    except (IndexError, ValueError):
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with MALFORMED_LOG_FILE.open("a") as err_file:
            err_file.write(f"[{now_str}] {line}\n")
        return None


def analyze_logs(log_file, suspicious_actions):
    """Aggregate failed attempts per user/IP. Timestamps stored as datetime objects."""
    failed_attempts = {}
    with log_file.open("r") as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed is None:
                continue

            timestamp_str, user, ip, action = parsed
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

            if action in suspicious_actions:
                key = (user, ip)
                if key not in failed_attempts:
                    failed_attempts[key] = []
                failed_attempts[key].append(timestamp)
    return failed_attempts


def write_csv_report(failed_attempts, report_file, threshold):
    """Write failed attempts to CSV for users/IPs exceeding threshold."""
    with report_file.open("w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["User", "IP Address", "Failed Attempts", "Timestamps"])
        for (user, ip), timestamps in failed_attempts.items():
            count = len(timestamps)
            if count >= threshold:
                ts_str = "|".join(ts.strftime("%Y-%m-%d %H:%M:%S") for ts in timestamps)
                writer.writerow([user, ip, count, ts_str])
                print(f"CSV report entry: User '{user}', IP {ip}, Attempts {count}")


def print_report(failed_attempts, threshold):
    """Print human-readable report for users/IPs exceeding threshold."""
    print(f"\nSuspicious Activity Report (threshold = {threshold} failed attempts):")
    for (user, ip), timestamps in failed_attempts.items():
        count = len(timestamps)
        if count >= threshold:
            print(f"User '{user}' from IP {ip} has {count} failed login attempts")
            print("  Timestamps:")
            for ts in timestamps:
                print(f"    - {ts.strftime('%Y-%m-%d %H:%M:%S')}")


# === ALERTING ===
def check_alerts(failed_attempts, threshold, time_window_minutes, alert_email=None):
    """Check for alerts and log them. Optional email notification is commented out."""
    time_window = timedelta(minutes=time_window_minutes)
    alerts = []

    for (user, ip), timestamps in failed_attempts.items():
        timestamps.sort()
        start = 0
        for end in range(len(timestamps)):
            while timestamps[end] - timestamps[start] > time_window:
                start += 1
            window_count = end - start + 1
            if window_count >= threshold:
                alert_msg = (f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ALERT: "
                             f"User '{user}' from IP {ip} had {window_count} failed attempts "
                             f"within {time_window_minutes} minutes.\n")
                alerts.append(alert_msg)

    if alerts:
        with ALERT_LOG_FILE.open("a") as f:
            f.writelines(alerts)

    # Email notification (uncomment to enable)
    """
    if alert_email and alerts:
        def send_email_alert(to_email, alerts):
            msg = EmailMessage()
            msg['Subject'] = 'Suspicious Activity Alert'
            msg['From'] = '<YOUR_EMAIL>'
            msg['To'] = to_email
            msg.set_content("The following alerts were generated:\n\n" + "".join(alerts))
            try:
                with smtplib.SMTP('<SMTP_SERVER>', <PORT>) as server:
                    server.starttls()
                    server.login('<USERNAME>', '<PASSWORD>')
                    server.send_message(msg)
                print(f"Alert email sent to {to_email}")
            except Exception as e:
                print(f"Failed to send alert email: {e}")
        send_email_alert(alert_email, alerts)
    """

    return alerts


# === MAIN WORKFLOW ===
if __name__ == "__main__":
    failed_attempts = analyze_logs(LOG_FILE, SUSPICIOUS_ACTIONS)
    print_report(failed_attempts, THRESHOLD)
    write_csv_report(failed_attempts, REPORT_FILE, THRESHOLD)
    alerts = check_alerts(failed_attempts, THRESHOLD, TIME_WINDOW_MINUTES)
    if alerts:
        print("\nALERTS GENERATED:")
        for alert in alerts:
            print(alert.strip())
