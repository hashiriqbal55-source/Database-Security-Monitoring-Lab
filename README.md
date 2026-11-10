Database Security Monitoring Lab

Project Overview

A Python-based database security monitoring project inspired by Database Activity Monitoring (DAM) and SOC operations.

This project uses PostgreSQL logs to identify potentially suspicious database activities, generate security alerts, and display investigation results through an HTML dashboard.

Note: This is an independent educational lab project, not the IBM Guardium product.

Features

* PostgreSQL database activity monitoring
* Sensitive employee data access detection
* Database modification detection
* Privilege modification detection
* Failed database login detection
* Suspicious user activity tracking
* Brute-force login detection by source IP
* Severity classification: LOW, MEDIUM, HIGH and CRITICAL
* Automated TXT security reports
* HTML security dashboard

Technologies Used

* Python
* PostgreSQL 18
* pgAdmin 4
* Visual Studio Code
* Regular Expressions (Regex)
* HTML and CSS

Project Structure

Guardium_Lab/
├── detection/
│   └── db_detector.py
├── logs/
├── database_security_report.txt
├── database_security_report.html
├── README.md
└── requirements.txt

How It Works

1. PostgreSQL records database activity in log files.
2. Python reads and analyzes the logs.
3. Detection rules identify suspicious SQL operations and authentication failures.
4. Alerts are assigned severity levels.
5. The system generates TXT and HTML security reports.

Detection Rules

Activity	Severity
Employee table access	MEDIUM
Sensitive salary data access	HIGH
Database modification	HIGH
Privilege modification	CRITICAL
Failed database login	HIGH
Repeated failed logins	CRITICAL

How to Run

Run the following command from the project directory:

py .\detection\db_detector.py

Open database_security_report.html in a web browser to view the dashboard.

Learning Outcomes

* PostgreSQL audit log analysis
* Database security monitoring
* SQL activity investigation
* Authentication failure investigation
* Brute-force detection
* Python-based security automation
* SOC alert analysis and reporting

Disclaimer

This project is developed for educational and authorized security testing purposes using a controlled local database environment.