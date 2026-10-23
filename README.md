# 🛡️ SOC Log Monitoring System

A Python-based Security Operations Center (SOC) monitoring application designed to collect, monitor, and analyze Windows security events, detect suspicious activities, and display security alerts through a Flask web dashboard.

## 📌 Project Overview

The SOC Log Monitoring System helps security analysts monitor Windows security events and identify potentially suspicious activities. It collects event information, applies threat-detection rules, and presents security-related information through a centralized dashboard.

This project is developed as a cybersecurity learning project to demonstrate security event monitoring, basic threat detection, event correlation, and incident investigation.

## ✨ Features

- **Windows Event Monitoring:** Collects Windows security events.
- **Threat Detection:** Identifies selected security events using detection rules.
- **SOC Dashboard:** Displays security events and alerts through a Flask web interface.
- **Event Severity Classification:** Categorizes events by severity.
- **Event Correlation:** Supports correlation of related security events.
- **Incident Investigation:** Provides pages for reviewing events and investigating incidents.
- **Alert Management:** Organizes security alerts and alert history.
- **Agent-Based Collection:** Uses a Python agent to send events to a central ingestion endpoint.
- **Persistent Event Queue:** Stores pending events locally for retry when delivery fails.
- **API-Key Authentication:** Protects the event ingestion endpoint using an API key.
- **SQLite Database:** Stores application data locally.

## 🧰 Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core application and monitoring logic |
| Flask | Web application and dashboard |
| SQLite | Local database storage |
| HTML and CSS | Dashboard interface |
| Windows Event Log | Security event collection |
| Requests | HTTP communication between agent and server |
| python-dotenv | Environment variable configuration |
| Git and GitHub | Version control and project hosting |

## 📂 Project Structure

```text
SOC-Log-Monitoring-System/
├── app.py
├── agent.py
├── config.py
├── requirements.txt
├── .gitignore
├── README.md
├── modules/
│   ├── alert_history.py
│   ├── alerting.py
│   ├── correlation_engine.py
│   ├── database.py
│   ├── event_reader.py
│   ├── risk_engine.py
│   ├── rules.py
│   ├── security_monitor.py
│   ├── threat_detection.py
│   └── validation.py
├── static/
│   └── style.css
└── templates/
    ├── index.html
    ├── alerts.html
    ├── event.html
    ├── incident.html
    ├── logs.html
    ├── report.html
    └── soc.html
```

*The structure above highlights the main application components; your actual repository may contain additional modules and templates.*

## ⚙️ Requirements

- Python 3.10 or a compatible version
- Windows for Windows Event Log collection
- pip
- Git (optional, for cloning the repository)

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/komal5676/SOC-Log-Monitoring-System.git
cd SOC-Log-Monitoring-System
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

Activate it in Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

If a `requirements.txt` file is available:

```bash
pip install -r requirements.txt
```

Otherwise, install the dependencies required by your application, for example:

```bash
pip install Flask requests python-dotenv pywin32
```

### 4. Configure environment variables

Create a local `.env` file in the project root:

```env
API_KEY=replace_with_your_own_secret_key
```

Use your own securely generated key. Do not upload `.env` to GitHub or share the key publicly.

The server and agent must use the same API key, and the HTTP header must match the authentication method configured in the Flask application.

### 5. Run the Flask application

```bash
python app.py
```

Open your browser at:

```text
http://127.0.0.1:5000
```

### 6. Run the monitoring agent

In another terminal, activate the virtual environment and run:

```bash
python agent.py
```

The agent requires the appropriate Windows permissions to read event logs and a running central server to send events.

## 🔐 Security Notes

- Keep API keys, passwords, webhook URLs, and other secrets out of source code.
- Store secrets in environment variables or a local `.env` file.
- Ensure `.env`, virtual environments, databases, and sensitive logs are excluded from Git when appropriate.
- Use only authorized computers and systems for monitoring.
- Review and restrict access to collected security events because they may contain sensitive information.

## 🎯 Learning Objectives

This project demonstrates:

- Security event collection and monitoring
- Basic threat detection and severity classification
- Centralized security event ingestion
- Event correlation and incident investigation
- Flask-based security dashboards
- API authentication and secure configuration
- Local event queueing and retry handling

## 🔮 Future Enhancements

- Real-time alert notifications
- Advanced detection rules and anomaly detection
- Integration with a SIEM platform
- Role-based access control
- Improved incident response workflows
- Dashboard analytics and reporting
- Multi-endpoint monitoring

## ⚠️ Project Scope

This is an educational cybersecurity project. It should not be considered a complete enterprise SIEM or a replacement for a production security monitoring platform. Detection coverage, authentication, access control, logging, and deployment security should be tested before production use.

## 👩‍💻 Author

**Komal Ghanchi**

Cybersecurity Student | Aspiring Security Analyst

GitHub: [komal5676](https://github.com/komal5676)

---

If you find this project useful for learning cybersecurity, feel free to explore the code and suggest improvements.
