import re
import html
from pathlib import Path
from datetime import datetime

DETECTION_RULES = {
    "Sensitive employee data access": {
        "pattern": r"\bSELECT\b.*\bsalary\b",
        "severity": "HIGH"
    },
    "Employee table access": {
        "pattern": r"\bSELECT\b.*\bFROM\s+employees\b",
        "severity": "MEDIUM"
    },
    "Database modification": {
        "pattern": r"\b(DELETE|DROP|TRUNCATE|UPDATE)\b",
        "severity": "HIGH"
    },
    "Privilege modification": {
        "pattern": r"\b(GRANT|REVOKE|ALTER\s+ROLE)\b",
        "severity": "CRITICAL"
    },
    "Failed database login": {
    "pattern": r"password authentication failed|authentication failed",
    "severity": "HIGH"
    },

}


def analyze_logs(log_file):
    alerts = []
    failed_login_attempts = {}

    with open(log_file, "r", encoding="utf-8", errors="ignore") as file:
        for line_number, line in enumerate(file, start=1):
            if re.search(
                r"password authentication failed|authentication failed",
                line,
                re.IGNORECASE
            ):
                host_match = re.search(r"HOST=([^|]+)", line)

                host_value = host_match.group(1).strip() if host_match else "Unknown"
                source_ip = host_value.split("(")[0].strip()

                failed_login_attempts[source_ip] = (
                    failed_login_attempts.get(source_ip, 0) + 1
                )

            for alert_name, rule in DETECTION_RULES.items():

                if re.search(rule["pattern"], line, re.IGNORECASE):

                    timestamp = re.search(r"^(.+?)\s+\|\s+USER=", line)
                    username = re.search(r"USER=([^|]+)", line)
                    database = re.search(r"DB=([^|]+)", line)
                    host = re.search(r"HOST=([^|]+)", line)
                    application = re.search(r"APP=([^|]+)", line)
                    sql = re.search(r"statement:\s*(.*)", line, re.IGNORECASE)

                    host_value = host.group(1).strip() if host else "Unknown"
                    host_ip = host_value.split("(")[0].strip()

                    alerts.append({
                        "line": line_number,
                        "alert": alert_name,
                        "severity": rule["severity"],
                        "timestamp": timestamp.group(1).strip() if timestamp else "Unknown",
                        "username": username.group(1).strip() if username else "Unknown",
                        "database": database.group(1).strip() if database else "Unknown",
                        "source_ip": host_ip,
                        "application": application.group(1).strip() if application else "Unknown",
                        "sql": sql.group(1).strip() if sql else "Unknown",
                        "evidence": line.strip()
                    })
    for source_ip, count in failed_login_attempts.items():
        if count >= 5:
            alerts.append({
                "line": "Multiple",
                "alert": "Possible Brute Force Attack",
                "severity": "CRITICAL",
                "timestamp": "Multiple attempts",
                "username": "Multiple/Unknown",
                "database": "guardium_lab",
                "source_ip": source_ip,
                "application": "PostgreSQL",
                "sql": f"{count} failed login attempts",
                "evidence": f"{count} failed login attempts from {source_ip}"
            })
    return alerts


if __name__ == "__main__":

    log_folder = Path("logs")

    total_alerts = 0
    all_alerts = []

    severity_counts = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0
    }
    user_activity = {}
    SUSPICIOUS_ACTIVITY_THRESHOLD = 5

    print("\n===== DATABASE SECURITY MONITOR =====")

    log_files = list(log_folder.glob("*.log"))

    for log_file in log_files:

        print(f"\nAnalyzing: {log_file.name}")

        alerts = analyze_logs(log_file)

        all_alerts.extend(alerts)
        total_alerts += len(alerts)

        for alert in alerts:
            severity_counts[alert["severity"]] += 1
            username = alert.get("username", "Unknown")
            user_activity[username] = user_activity.get(username, 0) + 1

            print("\n[ALERT DETECTED]")
            print(f"Type: {alert['alert']}")
            print(f"Severity: {alert['severity']}")
            print(f"Line: {alert['line']}")
            print(f"Evidence: {alert['evidence']}")

        print(f"\nFile alerts: {len(alerts)}")

    print("\n===== FINAL SECURITY SUMMARY =====")
    print(f"TOTAL ALERTS: {total_alerts}")

    print("\n===== SEVERITY BREAKDOWN =====")

    for severity, count in severity_counts.items():
        print(f"{severity}: {count}")
        print("\n===== USER ACTIVITY SUMMARY =====")

for username, count in sorted(user_activity.items()):
    print(f"User: {username} | Alerts: {count}")

    if count >= SUSPICIOUS_ACTIVITY_THRESHOLD:
        print(f"[WARNING] Suspicious activity detected for user: {username}")

    # Generate security investigation report

    report_file = Path("database_security_report.txt")

    with open(report_file, "w", encoding="utf-8") as report:

        report.write("===== DATABASE SECURITY INVESTIGATION REPORT =====\n\n")

        report.write(f"Total Alerts: {total_alerts}\n\n")

        report.write("===== SEVERITY BREAKDOWN =====\n")

        for severity, count in severity_counts.items():
            report.write(f"{severity}: {count}\n")

        report.write("\n===== ANALYZED LOG FILES =====\n")

        for log_file in log_files:
            report.write(f"{log_file.name}\n")

        report.write("\n===== DETECTED ALERTS =====\n")

        for alert in all_alerts:
            report.write("\n-----------------------------\n")
            report.write(f"Alert: {alert['alert']}\n")
            report.write(f"Severity: {alert['severity']}\n")
            report.write(f"Line: {alert['line']}\n")
            report.write(f"Evidence: {alert['evidence']}\n")

    print(f"\nSecurity report saved: {report_file}")
    # Generate HTML security dashboard

    html_file = Path("database_security_report.html")

user_rows = ""

for username, count in sorted(user_activity.items()):
    user_rows += f"""
    <tr>
        <td>{html.escape(username)}</td>
        <td>{count}</td>
    </tr>
    """
    alert_rows = ""

    for alert in all_alerts:
        severity = alert["severity"].lower()

        alert_rows = ""

    for alert in all_alerts:
        severity = alert["severity"].lower()

        alert_rows += f"""
        <tr>
            <td>{html.escape(alert["timestamp"])}</td>
            <td>{html.escape(alert["username"])}</td>
            <td>{html.escape(alert["database"])}</td>
            <td>{html.escape(alert["source_ip"])}</td>
            <td>{html.escape(alert["application"])}</td>
            <td>{html.escape(alert["alert"])}</td>
            <td>
                <span class="badge {severity}">
                    {html.escape(alert["severity"])}
                </span>
            </td>
            <td>{html.escape(alert["sql"])}</td>
        </tr>
        """
    max_count = max(severity_counts.values()) or 1

    severity_bars = ""

    for severity, count in severity_counts.items():
        percentage = (count / max_count) * 100

        severity_bars += f"""
        <p>{severity}: {count}</p>
        <div style="background:#334155; height:18px; border-radius:8px;">
            <div style="background:#38bdf8;
                        width:{percentage}%;
                        height:18px;
                        border-radius:8px;">
            </div>
        </div>
        """

    dashboard = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Database Security Dashboard</title>

        <style>
            body {{
                background: #101827;
                color: white;
                font-family: Arial, sans-serif;
                padding: 30px;
            }}

            h1 {{ color: #38bdf8; }}

            .cards {{
                display: flex;
                gap: 15px;
                flex-wrap: wrap;
                margin: 25px 0;
            }}

            .card {{
                background: #1e293b;
                padding: 20px;
                border-radius: 10px;
                min-width: 130px;
            }}

            .number {{
                font-size: 28px;
                font-weight: bold;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                background: #1e293b;
            }}

            th, td {{
                padding: 12px;
                border: 1px solid #334155;
                text-align: left;
                overflow-wrap: anywhere;
            }}

            th {{ color: #38bdf8; }}

            .badge {{
                padding: 5px 9px;
                border-radius: 5px;
            }}

            .high {{ background: #991b1b; }}
            .medium {{ background: #92400e; }}
            .critical {{ background: #7f1d1d; }}
            .low {{ background: #166534; }}
        </style>
    </head>

    <body>

        <h1>Database Security Monitoring Dashboard</h1>

        <p>PostgreSQL Security Investigation Report</p>

        <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>

        <div class="cards">

            <div class="card">
                <p>Total Alerts</p>
                <div class="number">{total_alerts}</div>
            </div>

            <div class="card">
                <p>Critical</p>
                <div class="number">{severity_counts["CRITICAL"]}</div>
            </div>

            <div class="card">
                <p>High</p>
                <div class="number">{severity_counts["HIGH"]}</div>
            </div>

            <div class="card">
                <p>Medium</p>
                <div class="number">{severity_counts["MEDIUM"]}</div>
            </div>

            <div class="card">
                <p>Low</p>
                <div class="number">{severity_counts["LOW"]}</div>
            </div>

        </div>
        <h2>Security Alert Distribution</h2>

<div style="background:#1e293b; padding:20px; border-radius:10px;">
    {severity_bars}
</div>
        <h2>Detected Security Events</h2>

        <table>
    <tr>
        <th>Timestamp</th>
        <th>Database User</th>
        <th>Database</th>
        <th>Source IP</th>
        <th>Application</th>
        <th>Alert Type</th>
        <th>Severity</th>
        <th>SQL Query</th>
    </tr>
<<h2>User Activity Summary</h2>

<table>
    <thead>
        <tr>
            <th>Database User</th>
            <th>Alert Count</th>
        </tr>
    </thead>
    <tbody>
        {user_rows}
    </tbody>
</table>

<h2>Security Alerts</h2>

<table>
    <!-- Your existing alert table headers -->
    <tbody>
        {alert_rows}
    </tbody>
</table>

    </body>
    </html>
    """

    html_file.write_text(dashboard, encoding="utf-8")

    print(f"HTML dashboard saved: {html_file}")