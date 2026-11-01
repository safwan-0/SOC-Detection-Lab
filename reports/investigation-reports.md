# SOC Detection Lab — Investigation Report

## 1. Project Overview

This investigation report documents the analysis of simulated security events using Elasticsearch and Kibana.

The objective was to investigate suspicious activities, identify potential security threats, and understand basic SOC analyst investigation workflows.

**Tools Used:**
- Elasticsearch 7.17.0
- Kibana 7.17.0
- Docker
- Ubuntu Linux
- Kibana Query Language (KQL)

**Total Events Analyzed:** 30

---

## 2. Detection 1: Brute-Force Login Attempts

**Objective:** Identify repeated failed authentication attempts from a single source IP.

**Observed Data:**
- Source IP: `192.168.1.50`
- Target Username: `admin`
- Failed Login Attempts: 6
- Subsequent Event: Successful Login

**KQL Query:**

```text
event_type : "login_failed" and source_ip : "192.168.1.50"
```

**Investigation Findings:**

Multiple failed login attempts were observed from the same source IP within a short time period. A successful login was recorded afterward.

**Assessment:** High-priority suspicious authentication activity.

**Recommended Actions:**
- Review the successful login session.
- Verify the account owner's activity.
- Investigate additional authentication records.
- Consider appropriate account protection measures if unauthorized access is confirmed.

---

## 3. Detection 2: Suspicious Successful Login

**Objective:** Investigate successful authentication following multiple failed login attempts.

**Observed Data:**
- Source IP: `192.168.1.50`
- Target Username: `admin`
- Previous Activity: Multiple failed login attempts
- Final Event: Successful Login

**KQL Query:**

```text
event_type : "login_success" and source_ip : "192.168.1.50"
```

**Investigation Findings:**

A successful login was observed from an IP address that had previously generated multiple failed authentication events.

**Assessment:** Potential account compromise requiring further investigation.

**Recommended Actions:**
- Review the login timeline.
- Verify whether the login was authorized.
- Examine subsequent account activity.
- Review session and authentication records.

---

## 4. Detection 3: Privilege Escalation Activity

**Objective:** Identify suspicious privilege-related activities.

**Observed Data:**
- Username: `developer`
- Source IP: `192.168.1.25`
- Events: Privilege Escalation and Sudo Command
- Additional Activity: Permission Change

**KQL Queries:**

```text
event_type : "privilege_escalation"
```

Additional investigation:

```text
event_type : "sudo_command" or event_type : "permission_change"
```

**Investigation Findings:**

Multiple privilege-related events were observed for the developer account.

These events require investigation to determine whether the activity was authorized.

**Assessment:** Potential privilege misuse.

**Recommended Actions:**
- Verify the user's authorization.
- Review privilege changes.
- Investigate relevant system audit logs.
- Examine the account's recent activity.

---

## 5. Detection 4: Suspicious Network Connection Attempts

**Objective:** Investigate repeated connection attempts from a single source IP.

**Observed Data:**
- Source IP: `192.168.1.90`
- Destination Port: `22`
- Connection Attempts: 5

**KQL Query:**

```text
event_type : "connection_attempt" and source_ip : "192.168.1.90"
```

**Investigation Findings:**

Multiple connection attempts targeting port 22 (SSH) were recorded from the same source IP within a short period.

**Assessment:** Repeated network connection activity requiring further investigation.

**Recommended Actions:**
- Review connection frequency.
- Investigate the source IP.
- Examine additional network traffic records.
- Determine whether the activity matches expected network behavior.

---

## 6. Overall Investigation Summary

| Detection Scenario | Observed Activity | Assessment |
|---|---|---|
| Brute-force Attempts | 6 failed logins followed by success | High-priority suspicious activity |
| Suspicious Login | Successful login after repeated failures | Potential account compromise |
| Privilege Escalation | Multiple privilege-related events | Potential privilege misuse |
| Network Activity | 5 SSH connection attempts | Suspicious activity requiring review |

---

## 7. Investigation Limitations

- All security events were simulated.
- The investigation used manually generated sample logs.
- No real production systems were monitored.
- Detection was performed using Kibana Discover and KQL queries.
- Automated alerting and incident response were not implemented.
- The available logs do not independently establish that an actual attack occurred.

---

## 8. Conclusion

This project demonstrates a basic SOC investigation workflow using the Elastic Stack.

Through simulated security events, four security scenarios were investigated, including repeated failed logins, suspicious successful authentication, privilege-related activity, and repeated network connection attempts.

The project provided practical experience with log ingestion, SIEM-based investigation, KQL queries, and security incident documentation.

**Project Status:** Initial Detection Lab Completed

**Future Scope:** Automated detection rules, Kibana dashboards, alerting, and Python-based security automation.
