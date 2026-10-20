# SOC Detection Report

Generated: 2026-10-20 20:13

## Summary

| Severity | Alerts |
|---|---|
| critical | 2 |
| high | 3 |
| medium | 5 |

## Alerts

### 1. [CRITICAL] brute_force_success — `203.0.113.77`

- **What happened:** 12 failed logins for 'bob' then SUCCESS from 203.0.113.77
- **MITRE ATT&CK:** T1078 - Valid Accounts
- **Time:** 2026-10-20T11:20:00 → 2026-10-20T11:21:40
- **Recommended response:** Treat account as compromised: disable it, kill sessions, reset credentials, hunt for post-login activity.

### 2. [CRITICAL] new_uid0_account — `svc_backup`

- **What happened:** New account 'svc_backup' created with UID 0 (root-equivalent)
- **MITRE ATT&CK:** T1136.001 - Create Account: Local Account
- **Time:** 2026-10-20T11:26:00 → 2026-10-20T11:26:00
- **Recommended response:** UID 0 means a root-equivalent backdoor. Disable the account immediately and start incident response.

### 3. [HIGH] ssh_brute_force — `203.0.113.50`

- **What happened:** 21 failed SSH logins from 203.0.113.50 within 60s
- **MITRE ATT&CK:** T1110.001 - Brute Force: Password Guessing
- **Time:** 2026-10-20T09:00:00 → 2026-10-20T09:01:00
- **Recommended response:** Block source IP at firewall, check for any successful login from it, enable fail2ban / key-only SSH.

### 4. [HIGH] password_spraying — `198.51.100.23`

- **What happened:** 10 distinct usernames tried from 198.51.100.23 within 600s
- **MITRE ATT&CK:** T1110.003 - Brute Force: Password Spraying
- **Time:** 2026-10-20T10:00:00 → 2026-10-20T10:06:45
- **Recommended response:** Block source IP, review targeted accounts, enforce MFA and account lockout policy.

### 5. [HIGH] sudo_group_add — `bob`

- **What happened:** bob was added to a privileged group
- **MITRE ATT&CK:** T1098 - Account Manipulation
- **Time:** 2026-10-20T11:27:00 → 2026-10-20T11:27:00
- **Recommended response:** Confirm a change ticket exists; if not, revert group membership and investigate who made the change.

### 6. [MEDIUM] sudo_denied — `bob`

- **What happened:** 3 denied sudo attempts by from bob within 300s
- **MITRE ATT&CK:** T1548.003 - Abuse Elevation Control: Sudo
- **Time:** 2026-10-20T11:23:00 → 2026-10-20T11:23:40
- **Recommended response:** Contact the user, review what they ran, confirm whether the session is legitimate.

### 7. [MEDIUM] root_shell — `bob`

- **What happened:** bob opened a root shell via sudo
- **MITRE ATT&CK:** T1548.003 - Abuse Elevation Control: Sudo
- **Time:** 2026-10-20T11:28:00 → 2026-10-20T11:28:00
- **Recommended response:** Verify it was an authorised admin action; review commands run in the root shell.

### 8. [MEDIUM] port_scan — `192.0.2.99`

- **What happened:** 100 distinct ports probed from 192.0.2.99 within 30s
- **MITRE ATT&CK:** T1046 - Network Service Discovery
- **Time:** 2026-10-20T13:00:00 → 2026-10-20T13:00:19
- **Recommended response:** Block or rate-limit source IP, check whether any probed port was open, watch for follow-up attacks.

### 9. [MEDIUM] scanner_user_agent — `203.0.113.9`

- **What happened:** Known scanner user-agent seen from 203.0.113.9
- **MITRE ATT&CK:** T1595.002 - Active Scanning: Vulnerability Scanning
- **Time:** 2026-10-20T14:00:00 → 2026-10-20T14:00:59
- **Recommended response:** Block source IP at WAF; scanner tools are rarely used by legitimate users.

### 10. [MEDIUM] web_scan_404 — `203.0.113.9`

- **What happened:** 59 HTTP 404 responses from 203.0.113.9 within 60s
- **MITRE ATT&CK:** T1595.003 - Active Scanning: Wordlist Scanning
- **Time:** 2026-10-20T14:00:01 → 2026-10-20T14:00:59
- **Recommended response:** Block source IP at WAF, check whether any probed path returned 200.

## Detection quality (vs. ground truth)

- Precision: **1.0**  Recall: **1.0**
- Missed: none
- False positives: none
