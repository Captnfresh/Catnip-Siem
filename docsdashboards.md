# Dashboards — Security Visualisation 

 

**Contributor:** Akhamas Balouch   

**Role:** Dashboards   

**Project:** Catnip Games International SIEM   

 

--- 

 

## Overview 

 

My responsibility was designing and building the five security  

dashboards that give the Catnip Games SOC team real-time  

visibility into their infrastructure. Each dashboard answers  

a specific set of security questions at a glance. 

 

--- 

 

## Dashboard Design Principles 

 

**Each widget answers one question.** 

Before building any widget, the question it answers was defined  

first. "What happened?" "Who is attacking?" "Which servers are  

targeted?" Widgets that don't answer a clear question don't  

belong on a dashboard. 

 

**Titles describe what, not when.** 

Widget titles like "Failed SSH Logins" rather than "Failed SSH  

Logins Last 24 Hours" — because the Global Override time control  

changes the time range dynamically. Hardcoding time in titles  

creates misleading displays when the range changes. 

 

**Global Override for demonstrations.** 

The dashboard-level time override updates all widgets  

simultaneously. This allows showing different time perspectives  

in one click during demonstrations without editing individual  

widgets. 

 

--- 

 

## Dashboard 1 — Security Overview 

 

**Purpose:** High-level summary of all activity across the entire  

Catnip Games infrastructure. First screen a SOC analyst sees  

each morning. 

 

**Stream:** All streams (no filter) 

 

### Widget 1 — Total Log Events 

- Type: Single Number with Trend 

- Query: `*` (all events) 

- Trend preference: Lower (more events = more concern) 

- Answers: "How busy was the infrastructure today?" 

 

### Widget 2 — Event Volume Timeline 

- Type: Line Chart 

- Query: `*` 

- Group By: timestamp (Auto interval) 

- Answers: "When did activity spike?" 

 

### Widget 3 — Log Sources Breakdown 

- Type: Pie Chart 

- Query: `*` 

- Group By: event_type 

- Answers: "What kinds of events are happening?" 

 

### Widget 4 — Critical Threat Events 

- Type: Single Number with Trend 

- Query: `severity:critical` 

- Trend preference: Lower 

- Answers: "How many serious threats occurred?" 

 

--- 

 

## Dashboard 2 — SSH Auth Monitoring 

 

**Purpose:** Detailed view of SSH authentication activity —  

brute force detection, attacker analysis, and login outcomes. 

 

**Stream:** ssh-auth 

 

### Widget 1 — Failed SSH Logins Over Time 

- Type: Bar Chart 

- Query: `event_type:sshd AND action:failed` 

- Group By: timestamp 

- Answers: "When are SSH attacks happening?" 

 

### Widget 2 — Top Attacking IPs 

- Type: Bar Chart 

- Query: `event_type:sshd AND action:failed` 

- Group By: source_ip 

- Answers: "Which IPs are generating the most failed attempts?" 

 

### Widget 3 — Most Targeted Usernames 

- Type: Bar Chart 

- Query: `event_type:sshd AND action:failed` 

- Group By: username, Sort: Descending 

- Answers: "Which accounts are being targeted?" 

 

### Widget 4 — SSH Login Outcomes 

- Type: Bar Chart (Stacked) 

- Query: `event_type:sshd` 

- Group By: timestamp (Row), action (Column) 

- Answers: "What is the ratio of successful vs failed logins?" 

 

**Design note:** Stacked bar chart was chosen over a pie chart  

because it shows both the ratio and the volume over time — two  

pieces of information in one widget. 

 

--- 

 

## Dashboard 3 — Game Server Health 

 

**Purpose:** Monitor traffic levels, DDoS attacks, and server  

health across Catnip's 300 game servers. 

 

**Stream:** game_server 

 

### Widget 1 — DDoS Attacks Over Time 

- Type: Bar Chart 

- Query: `event_type:game_traffic AND action:ddos_detected` 

- Group By: timestamp 

- Answers: "When are DDoS attacks occurring?" 

 

### Widget 2 — Top Targeted Game Servers 

- Type: Pie Chart 

- Query: `event_type:game_traffic AND action:ddos_detected` 

- Group By: server_id 

- Answers: "Which game servers are being attacked most?" 

 

### Widget 3 — Traffic Volume Over Time 

- Type: Bar Chart 

- Query: `event_type:game_traffic` 

- Group By: timestamp 

- Answers: "What does overall traffic look like?" 

 

### Widget 4 — Normal vs DDoS Traffic 

- Type: Bar Chart (Stacked) 

- Query: `event_type:game_traffic` 

- Group By: timestamp (Row), action (Column) 

- Answers: "What proportion of traffic is attack traffic?" 

 

--- 

 

## Dashboard 4 — Player Auth Monitoring 

 

**Purpose:** Track player login activity, detect credential  

stuffing attacks, and identify targeted player accounts. 

 

**Stream:** game_server 

 

### Widget 1 — Player Login Outcomes Over Time 

- Type: Bar Chart (Stacked) 

- Query: `event_type:player_auth` 

- Group By: timestamp (Row), action (Column) 

- Answers: "How are player login attempts trending?" 

 

### Widget 2 — Top Targeted Players 

- Type: Pie Chart 

- Query: `event_type:player_auth AND action:login_failed` 

- Group By: username 

- Answers: "Which player accounts are being targeted?" 

 

### Widget 3 — Credential Stuffing Over Time 

- Type: Bar Chart 

- Query: `event_type:player_auth AND action:credential_stuffing` 

- Group By: timestamp 

- Answers: "When are credential stuffing attacks occurring?" 

 

### Widget 4 — Top Attacker IPs (Player Auth) 

- Type: Bar Chart 

- Query: `event_type:player_auth AND action:login_failed` 

- Group By: source_ip 

- Answers: "Which IPs are attacking player accounts?" 

 

--- 

 

## Dashboard 5 — Dev Environment Security 

 

**Purpose:** Monitor SSH activity across Catnip's developer  

servers — the environment compromised during the beta period  

according to the security brief. 

 

**Stream:** game_server 

 

### Widget 1 — Dev SSH Activity Over Time 

- Type: Bar Chart (Stacked) 

- Query: `event_type:dev_ssh` 

- Group By: timestamp (Row), action (Column) 

- Answers: "What is the overall dev SSH activity pattern?" 

 

### Widget 2 — Suspicious vs Normal Dev Logins 

- Type: Bar Chart (Stacked) 

- Query: `event_type:dev_ssh` 

- Group By: timestamp (Row), action (Column) 

- Answers: "What proportion of dev logins are suspicious?" 

 

### Widget 3 — Top Targeted Dev Accounts 

- Type: Bar Chart 

- Query: `event_type:dev_ssh AND action:suspicious_login` 

- Group By: username 

- Answers: "Which developer accounts are being targeted?" 

 

### Widget 4 — Top Suspicious Source IPs 

- Type: Bar Chart 

- Query: `event_type:dev_ssh AND action:suspicious_login` 

- Group By: source_ip 

- Answers: "Which IPs are attempting dev server access?" 

 

--- 

 

## Key Learning 

 

The most significant design challenge was understanding the  

difference between the Global Override time control and  

individual widget time settings. A widget's individual time  

range is its default — but the dashboard-level Global Override  

supersedes all widgets simultaneously. Understanding this  

hierarchy allowed building dashboards that work correctly  

both at their default settings and when an analyst adjusts  

the time range during an investigation. 
