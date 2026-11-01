# SOC Detection Lab Using Elastic Stack

A beginner-friendly Security Operations Center (SOC) detection lab built using Elasticsearch and Kibana.

This project demonstrates how security analysts can collect, analyze, and investigate simulated security events using SIEM tools.

## Project Objectives

- Generate simulated security logs.
- Ingest logs into Elasticsearch.
- Analyze security events using Kibana.
- Investigate suspicious authentication activities.
- Identify potential privilege escalation.
- Investigate repeated network connection attempts.
- Document findings through SOC investigation reports.

## Tools & Technologies

- Ubuntu Linux
- Docker
- Elasticsearch 7.17.0
- Kibana 7.17.0
- Python 3
- Kibana Query Language (KQL)

## Project Architecture

```text
Simulated Security Logs
          |
          v
       auth.log
          |
          v
     Python Parser
          |
          v
       bulk.json
          |
          v
    Elasticsearch
          |
          v
        Kibana
          |
          v
  Security Investigation
          |
          v
   Investigation Report
```

## Detection Scenarios

| No. | Detection Scenario | Investigation |
|---|---|---|
| 1 | Brute-force attempts | Repeated failed login attempts |
| 2 | Suspicious successful login | Successful login following multiple failed attempts |
| 3 | Privilege escalation | Suspicious privilege-related events |
| 4 | Suspicious network activity | Repeated network connection attempts |

## Repository Structure

```text
soc-detection-lab/
│
├── logs/
│   ├── auth.log
│   └── bulk.json
│
├── detections/
│   └── detection-queries.md
│
├── screenshots/
│   ├── login-failed.png
│   ├── brute-force.png
│   ├── privilege-escalation.png
│   └── network-activity.png
│
├── reports/
│   └── investigation-report.md
│
├── .gitignore
└── README.md
```

## Investigation Screenshots

### 1. Authentication Log Analysis

![Login Failed Events](screenshots/login-failed.png)

### 2. Brute-Force Detection

![Brute Force Detection](screenshots/brute-force.png)

### 3. Privilege Escalation Analysis

![Privilege Escalation](screenshots/privilege-escalation.png)

### 4. Suspicious Network Activity

![Network Activity](screenshots/network-activity.png)

## How It Works

1. Generate simulated security events.
2. Parse the logs into JSON format using Python.
3. Ingest the events into Elasticsearch using the Bulk API.
4. Create a Kibana Data View.
5. Investigate events using Kibana Discover and KQL.
6. Document suspicious activities in an investigation report.

## Sample Detection Queries

### Failed Login Attempts

```text
event_type : "login_failed"
```

### Privilege Escalation

```text
event_type : "privilege_escalation"
```

### Suspicious Successful Login

```text
event_type : "login_success" and source_ip : "192.168.1.50"
```

### Repeated Network Connection Attempts

```text
event_type : "connection_attempt" and source_ip : "192.168.1.90"
```

## Investigation Reports

Detailed investigation findings are documented in:

`reports/investigation-report.md`

Detection queries are documented in:

`detections/detection-queries.md`

## Project Limitations

- All security events are simulated.
- Detection currently relies on manual Kibana queries.
- Automated alerting and incident response are not implemented.
- Findings require additional evidence before being classified as confirmed security incidents.

## Future Improvements

- Add more realistic security log sources.
- Create automated detection rules.
- Build a Kibana security dashboard.
- Add alerting and notification capabilities.
- Integrate Python-based detection automation.

## Disclaimer

This project is created for educational and cybersecurity learning purposes. All logs are simulated and do not represent real attacks or real security incidents.

---

**Project:** SOC Detection Lab  
**SIEM:** Elastic Stack  
**Focus:** Blue Team | SOC Analysis | Log Investigation
