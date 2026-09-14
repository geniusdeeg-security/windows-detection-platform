```markdown
# Windows Detection Platform

**Windows threat detection and telemetry analysis using Sysmon, Sigma rules, and custom detection engineering workflows.**

## Why I Built This Project

Windows environments generate large volumes of security telemetry that can be difficult to analyze manually.

This project demonstrates how Sysmon telemetry, Sigma-based detection engineering, MITRE ATT&CK mapping, and event correlation can be used to identify suspicious activity and generate investigation-ready alerts.

## Project Highlights

- Sysmon telemetry analysis
- Detection engineering
- Sigma rule implementation
- MITRE ATT&CK mapping
- Event correlation
- Alert generation
- PostgreSQL-backed event storage
- Security dashboard development

## Project Outcome

This project demonstrates how Sysmon telemetry, detection engineering, Sigma-based analytics, and MITRE ATT&CK mapping can be combined to identify suspicious Windows activity and generate investigation-ready alerts for security operations teams.

## Security Skills Demonstrated

- Detection Engineering
- Windows Security Monitoring
- Sysmon Analysis
- Sigma Rules
- Threat Detection
- Event Correlation
- MITRE ATT&CK Mapping
- Incident Investigation
- PostgreSQL Database Design
- Security Automation

## 🎯 What This System Detects

✅ **Suspicious Process Chains** - explorer.exe → cmd.exe → powershell.exe  
✅ **Registry Persistence** - RunKey modifications, autoruns  
✅ **Privilege Escalation** - UAC bypass, token theft  
✅ **Malware Behavior** - File creation, network connections  
✅ **Command Obfuscation** - Encoded PowerShell commands  
✅ **Network Anomalies** - Suspicious C2 communication  


## 🏗️ Technical Architecture

```
Sysmon Event Collection 
  - Event ID 1 (Process Creation)
  - Event ID 3 (Network Connection)
  - Event ID 11 (File Creation)
  - Event ID 13 (Registry Modification)
  - Event ID 22 (DNS Query)
        ↓
Event Parsing & Normalization
        ↓
PostgreSQL Database Storage
        ↓
Baseline Engine (Normal behavior)
        ↓
Detection Engine (Custom Detection Rules)
        ↓
MITRE Mapping
        ↓
Alert Generation
        ↓
SIEM Export
```

## 📊 Sysmon Events Monitored

- **Event 1:** Process Creation
- **Event 3:** Network Connection
- **Event 11:** File Created
- **Event 13:** Registry Value Set
- **Event 15:** File Stream Hash
- **Event 22:** DNS Query

## 🔍 Sample Detection Rules

### Rule 1: Suspicious PowerShell Encoded Command
```
Severity: HIGH
Event: Process Creation (Event 1)
Detection: Suspicious PowerShell execution pattern
Result: Suspicious execution activity detected
```

### Rule 2: Registry Run Key Modification
```
Severity: HIGH
Event: Registry Value Set (Event 13)
Detection: Registry persistence activity
Result: Persistence mechanism detected
```

### Rule 3: PowerShell Network Connection
```
Severity: HIGH
Event: Network Connection (Event 3)
Detection: Suspicious outbound PowerShell communication
Result: Potential C2 communication
```

## 📋 Sample Alert Output

```
[HIGH] Suspicious Process Chain Detected

Process Chain:
  explorer.exe (legitimate)
    └─ cmd.exe (suspicious)
        └─ powershell.exe (malicious)
            └─ connection to External IP Address And PORT

ALERT DETAILS:
  Severity: High
  MITRE: T1059.001 (PowerShell)
  
EVIDENCE:
  Command: Suspicious PowerShell execution observed
  Registry: Suspicious persistence activity observed
  Network: C2 communication to External IP Address And PORT
  
ACTION: Isolate host, kill processes, preserve memory dump
```

## 🔧 Technology Stack

- **Python 3.8+** - Detection engine
- **Sysmon** - Windows telemetry collection
- **PostgreSQL** - Event storage
- **Sigma Rules** - Detection patterns
- **Flask** - Web dashboard
- **Pandas** - Data analysis

## 📦 Requirements

```
pandas
sqlalchemy
psycopg2-binary
flask
pyyaml
python-dateutil
python-evtx
```

## 🚀 Quick Start

```bash
git clone https://github.com/geniusdeeg-security/windows-detection-platform
cd windows-detection-platform
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
./run_pipeline.sh
```
## Project Structure

```text
windows-detection-platform/
│
├── Data Collection
│   ├── event_collector.py
│   └── event_parser.py
│
├── Detection Engine
│   ├── detection_engine.py
│   ├── sigma_engine.py
│   ├── baseline_engine.py
│   ├── threat_intel_engine.py
│   └── alert_manager.py
│
├── MITRE ATT&CK Mapping
│   ├── mitre_mapper.py
│   └── mitre/
│
├── Detection Content
│   └── sigma_rules/
│
├── Dashboard
│   ├── dashboard.py
│   └── templates/
│
├── Database
│   ├── database_schema.sql
│   └── baseline_schema.sql
│
├── SIEM & Exports
│   ├── siem_exporter.py
│   └── exports/
│
├── Automation
│   └── run_pipeline.sh
│
├── Supporting Data
│   ├── logs/
│   ├── reports/
│   └── structure.txt
│
├── requirements.txt
└── README.md
```

## Database Schema

```sql
-- Sysmon events 
CREATE TABLE sysmon_events (...);

-- Detection alerts
CREATE TABLE alerts (...);

-- Detection rules
CREATE TABLE detection_rules (...);
```

## Repository Scope

This repository contains the core detection framework used for learning, research, and portfolio demonstration purposes.

Sensitive deployment-specific configurations, integrations, tuning parameters, and operational workflows are intentionally excluded.

### Public Components

✅ Detection framework
✅ Sysmon event parsing
✅ Detection engine  
✅ MITRE mapping  

### Private Components
❌ **Rule Tuning** - Customize for YOUR environment  
❌ **False Positive Reduction** - Tune thresholds  
❌ **SIEM Integration** - Connect to YOUR tools  
❌ **Baseline Profiles** - Learn YOUR network  


## Screenshots

### Dashboard Overview

<img width="962" height="936" alt="Screenshot From 2026-09-10 09-18-41" src="https://github.com/user-attachments/assets/e2d08637-8569-4d1a-8c5f-11f638836d53" />

<img width="962" height="936" alt="Screenshot From 2026-09-10 09-18-58" src="https://github.com/user-attachments/assets/f13b4053-03f6-4ee2-8e80-01198504db80" />

<img width="962" height="936" alt="Screenshot From 2026-09-10 09-19-13" src="https://github.com/user-attachments/assets/aefa8b81-5f44-46a7-9a2d-430265b41926" />

### Detection Results

<img width="962" height="936" alt="Screenshot From 2026-09-10 09-19-28" src="https://github.com/user-attachments/assets/6da4acb2-1f2c-4eaf-8ef8-8da868b548b6" />

<img width="962" height="936" alt="Screenshot From 2026-09-10 09-19-37" src="https://github.com/user-attachments/assets/e0cc7fe2-3849-4ef3-bc16-a973d4d881b8" />

<img width="962" height="936" alt="Screenshot From 2026-09-10 09-19-49" src="https://github.com/user-attachments/assets/118f6d76-46c5-493e-a427-78cd36b22300" />

### Database Events

<img width="903" height="945" alt="Screenshot From 2026-09-10 09-24-50" src="https://github.com/user-attachments/assets/7c0c33b7-cbd5-4e80-aec8-37445ecca275" />

<img width="903" height="945" alt="Screenshot From 2026-09-10 09-25-29" src="https://github.com/user-attachments/assets/978d6caa-1b1b-494e-84a4-ee1c6c87139d" />


### Detection Pipeline Execution

<img width="903" height="945" alt="Screenshot From 2026-09-10 09-25-52" src="https://github.com/user-attachments/assets/17d6301a-1ba4-40bb-bca0-124079e719fe" />

<img width="944" height="962" alt="Screenshot From 2026-09-10 09-22-03" src="https://github.com/user-attachments/assets/5b67e93d-1bb6-4384-bd2e-d1fa8a71121e" />

<img width="944" height="962" alt="Screenshot From 2026-09-10 09-22-28" src="https://github.com/user-attachments/assets/8a133061-a909-4f86-8c6a-5f25227cf5ab" />

<img width="944" height="962" alt="Screenshot From 2026-09-10 09-22-43" src="https://github.com/user-attachments/assets/d588da9d-9335-474f-918c-3dc4e9e767cb" />

<img width="918" height="412" alt="Screenshot From 2026-09-10 09-23-05" src="https://github.com/user-attachments/assets/21041ebe-e2f2-49c7-9758-f8d69a29aaa4" />


## Connect With Me

* **LinkedIn:** [Charles Arinze](https://www.linkedin.com/in/charlesarinze)
* **GitHub:** [geniusdeeg-security](https://github.com/geniusdeeg-security)
* **Jobberman:** Available on my Jobberman professional profile



## MITRE ATT&CK Coverage

- T1059.001 (PowerShell)
- T1059.003 (Windows Command Shell)
- T1547 (Boot or Logon Autostart)
- T1543 (Create or Modify System Process)
- T1112 (Modify Registry)
- T1566 (Phishing)

## Status

✅ Fully Functional Lab Implementation
✅ Tested End-to-End
✅ Portfolio Project


## Career Interests

Open To:
- Remote Roles
- Hybrid Roles
- On-Site Roles
- Paid Internship Opportunities

Target Roles:
- Detection Engineer
- Security Analyst
- SOC Analyst
- SOC Analyst II
- Threat Hunter
- Blue Team Analyst


## License

This project is licensed under the MIT License. See the LICENSE file for details.
---

**Built by:** ARINZE CHARLES
```

---
