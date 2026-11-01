# SOC Detection Lab — Detection Queries

## 1. Brute-Force Login Attempts

**Objective:** Identify repeated failed login attempts from the same source IP.

```text
event_type : "login_failed"
```

Focused investigation:

```text
event_type : "login_failed" and source_ip : "192.168.1.50"
```

**Investigation:** Review the number of failed logins, targeted username, source IP, and whether a successful login followed.

## 2. Suspicious Successful Login

**Objective:** Investigate successful logins associated with previously observed failed attempts.

```text
event_type : "login_success" and source_ip : "192.168.1.50"
```

**Investigation:** Correlate successful login events with earlier failed login events from the same source IP.

## 3. Privilege Escalation Activity

**Objective:** Identify simulated privilege escalation events.

```text
event_type : "privilege_escalation"
```

Additional investigation:

```text
event_type : "sudo_command" or event_type : "permission_change"
```

**Investigation:** Review the affected username, source IP, event timestamp, and whether the activity was authorized.

## 4. Repeated Network Connection Attempts

**Objective:** Identify repeated connection attempts from a specific source IP.

```text
event_type : "connection_attempt" and source_ip : "192.168.1.90"
```

**Investigation:** Review the number of connection attempts and destination ports. Additional network telemetry is required to confirm port scanning or malicious activity.

## Limitations

These queries use simulated security logs and Kibana Query Language (KQL). They are investigation queries, not fully automated detection rules. The results alone do not confirm that a real attack occurred.
