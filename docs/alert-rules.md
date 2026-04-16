# Alert Rules — Event Definitions and Notifications

**Contributor:** Faith Okonoboh   
**Role:** Alerts  
**Project:** Catnip Games International SIEM  

---

## Overview

My responsibility was designing and implementing the alerting 
system — the rules that detect suspicious activity and 
automatically notify the security team via email.

Four alert rules were implemented covering the primary threat 
scenarios identified in the Catnip Games security brief.

---

## Alert Architecture

Alerts in Graylog work through two components that work together:

**Notifications** define *how* to alert — email address, subject 
line, message format. One shared notification was created and 
reused across all alert rules.

**Event Definitions** define *when* to alert — the query, 
threshold, time window, and which notification to trigger.

---

## Email Notification Setup

A single shared notification called **Catnip SIEM Email 
Notification** was created and attached to all four alert rules.

| Setting | Value |
|---|---|
| Type | Email |
| Recipients | youremail@gmail.com |
| Subject | [CatnipSIEM] Security Alert — ${event.message} |
| Grace period | 5 minutes |
| Message backlog | 50 |

**SMTP Configuration:**
Email delivery uses Gmail SMTP configured as environment variables 
in `docker-compose.yml`:
SMTP Host: smtp.gmail.com SMTP Port: 587 TLS: enabled Authentication: Gmail App Password

A Gmail App Password was required because Google blocks third-party 
applications from using standard Gmail passwords. The App Password 
is a 16-character code generated specifically for Graylog.

---

## Alert Rules

### Alert 1 — SSH Brute Force Detection

**Purpose:** Detect when a single IP address is repeatedly failing 
SSH login attempts — a classic brute force attack pattern.

| Setting | Value |
|---|---|
| Priority | High |
| Query | `event_type:sshd AND action:failed` |
| Stream | ssh-auth |
| Search within | 5 minutes |
| Execute every | 5 minutes |
| Condition type | Aggregation |
| Condition | count() >= 10 grouped by source_ip |

**Detection logic:**
When a single IP address generates 10 or more failed SSH login 
attempts within a 5 minute window, this indicates systematic 
automated password guessing rather than a legitimate user 
mistyping their password.

**Remediation steps:**
1. Block the source IP at the firewall immediately
2. Review which usernames were targeted
3. Check whether any login from the same IP succeeded
4. Reset passwords for any targeted accounts
5. Review `/var/log/auth.log` on affected servers
6. Add IP to threat intelligence blocklist
7. Consider implementing fail2ban for automated blocking

---

### Alert 2 — DDoS Attack Detected

**Purpose:** Detect Distributed Denial of Service attacks against 
Catnip game servers immediately — any single DDoS event is serious 
enough to trigger an alert.

| Setting | Value |
|---|---|
| Priority | High |
| Query | `event_type:game_traffic AND action:ddos_detected` |
| Stream | game_server |
| Search within | 5 minutes |
| Execute every | 5 minutes |
| Condition type | Filter has results |
| Condition | Any matching event triggers immediately |

**Detection logic:**
Unlike brute force which requires a threshold count, any DDoS 
detection event is immediately critical. The game server log 
generator marks events as `ddos_detected` when traffic exceeds 
normal thresholds. A single such event warrants immediate response.

**Remediation steps:**
1. Activate DDoS mitigation controls
2. Block source IP at network perimeter
3. Enable rate limiting on affected game servers
4. Notify game server operations team
5. Monitor `traffic_mbps` field for escalation
6. Consider activating Cloudflare or upstream mitigation service
7. Communicate server degradation to player community if needed

---

### Alert 3 — Credential Stuffing Attack

**Purpose:** Detect automated credential stuffing attacks against 
the player authentication system — where attackers use lists of 
previously breached username/password combinations.

| Setting | Value |
|---|---|
| Priority | High |
| Query | `event_type:player_auth AND action:credential_stuffing` |
| Stream | game_server |
| Search within | 5 minutes |
| Execute every | 5 minutes |
| Condition type | Aggregation |
| Condition | count() >= 20 grouped by source_ip |

**Detection logic:**
Credential stuffing attacks send large volumes of login attempts 
using breached credentials. 20 attempts from a single IP within 
5 minutes indicates automated tooling rather than a human user. 
The threshold of 20 was chosen to avoid false positives from 
legitimate high-frequency player activity.

**Remediation steps:**
1. Block source IP immediately
2. Force password reset for all targeted player accounts
3. Enable CAPTCHA on the player login endpoint
4. Check whether any attempts resulted in successful login
5. Implement account lockout after N failed attempts
6. Review for lateral movement if accounts were compromised
7. Notify affected players via email

---

### Alert 4 — Suspicious Dev SSH Login

**Purpose:** Detect suspicious SSH access to developer servers — 
this was the attack vector that went undetected during the Catnip 
Games beta period according to the security brief.

| Setting | Value |
|---|---|
| Priority | High |
| Query | `event_type:dev_ssh AND action:suspicious_login` |
| Stream | game_server |
| Search within | 5 minutes |
| Execute every | 5 minutes |
| Condition type | Filter has results |
| Condition | Any suspicious dev login triggers immediately |

**Detection logic:**
Any login to a developer server from an attacker IP is 
immediately critical — there is no safe threshold. The dev 
environment contains source code, deployment credentials, and 
access to production game servers. A single suspicious login 
means potential full infrastructure compromise.

**Remediation steps:**
1. Revoke SSH access for the affected user account immediately
2. Verify the source IP against known engineer locations
3. Review all commands executed during the session
4. Force password and SSH key rotation for affected accounts
5. Check for lateral movement from dev to production servers
6. Review git commit history for suspicious code changes
7. Conduct full incident response if compromise confirmed

---

## Alert Design Decisions

**Why four alerts and not more:**
The four alerts cover the primary threat vectors identified in 
the Catnip Games brief — SSH brute force, DDoS, credential 
stuffing, and dev environment compromise. Additional alerts 
would increase noise without adding proportional detection 
value at this stage.

**Why different condition types:**
SSH brute force and credential stuffing use aggregation 
thresholds because individual events are not inherently 
suspicious — it is the volume that indicates an attack. DDoS 
and suspicious dev SSH use "filter has results" because any 
single event is immediately critical regardless of volume.

**Why 5 minute windows:**
Five minute windows balance detection speed against false 
positive rate. Shorter windows increase sensitivity but 
generate more noise. Longer windows delay detection. Five 
minutes was selected as appropriate for the threat types 
being monitored.

---

## Key Learning

The most significant insight from this role was understanding 
the difference between threshold-based and immediate alerting. 
Not all security events require a count before acting — some 
events are critical on their own. Understanding when to use 
aggregation conditions versus filter conditions, and how to 
set appropriate thresholds that balance sensitivity against 
alert fatigue, was the central technical skill developed in 
this role.

