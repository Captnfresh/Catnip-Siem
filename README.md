# Catnip Games International — Security Monitoring SIEM

[![Graylog](https://img.shields.io/badge/Graylog-6.1-orange)](https://graylog.org)
[![OpenSearch](https://img.shields.io/badge/OpenSearch-2.15.0-blue)](https://opensearch.org)
[![MongoDB](https://img.shields.io/badge/MongoDB-7-green)](https://mongodb.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED)](https://docker.com)
[![Python](https://img.shields.io/badge/Python-3.x-yellow)](https://python.org)

A centralised Security Information and Event Management (SIEM) 
platform built for Catnip Games International which is a rapidly growing 
gaming company requiring comprehensive security monitoring across 
300 game servers, player authentication systems, and developer 
environments.

Built as part of the Cyber Security Automation module at the 
University of Roehampton. DCWF 511 — Cyber Defense Analyst 
work role.

---

## The Problem We Solved

During Catnip Games' beta testing phase, three critical security 
incidents went undetected for several days:

- Unauthorised access attempts to player data
- Potential DDoS attacks targeting game servers
- Suspicious activity in development environments

The root cause was fragmented logging and manual monitoring. 
Logs lived on individual servers with no central visibility. 
There were no automated alerts. Nobody was watching.

This project builds the solution which is a centralised SIEM that 
collects, parses, visualises, and alerts on security events 
across the entire Catnip Games infrastructure in real time.

---

## What This System Does

- Collects real SSH authentication logs from Linux servers
- Simulates game server, player auth, and DDoS log events
- Parses raw log messages into structured searchable fields
- Routes events into logical streams for targeted analysis
- Displays real-time security data across 5 dashboards
- Detects threats automatically using 4 alert rules
- Sends email notifications when attacks are detected
- Generates weekly automated security reports

---

## Architecture

┌─────────────────────────────────────────────────────┐ │ LOG SOURCES │ │ SSH/Auth logs Game servers Player auth │ │ (rsyslog/TCP) (Python GELF) (Python GELF) │ └──────────────┬──────────────┬───────────────────────┘ │ │ ▼ ▼ ┌─────────────────────────────────────────────────────┐ │ GRAYLOG INPUTS │ │ Syslog TCP:1514 Syslog UDP:1514 GELF UDP:12201 │ └──────────────────────┬──────────────────────────────┘ │ ▼ ┌─────────────────────────────────────────────────────┐ │ PARSING & NORMALISATION │ │ Extractors → event_type, action, username, │ │ source_ip │ └──────────────────────┬──────────────────────────────┘ │ ▼ ┌─────────────────────────────────────────────────────┐ │ STREAMS │ │ ssh-auth stream game-server stream │ └──────────┬──────────────────────┬───────────────────┘ │ │ ▼ ▼ ┌─────────────────────────────────────────────────────┐ │ OPENSEARCH (Storage + Search) │ └──────────┬──────────────────────┬───────────────────┘ │ │ ▼ ▼ ┌──────────────────┐ ┌──────────────────────────────┐ │ 5 DASHBOARDS │ │ 4 ALERT RULES │ │ 20 widgets │ │ Email notifications │ └──────────────────┘ └──────────────────────────────┘ │ ▼ ┌──────────────────┐ │ PYTHON REPORT │ │ Weekly summary │ └──────────────────┘

---

## Tech Stack

| Component | Version | Purpose |
|---|---|---|
| Graylog | 6.1 | SIEM brain, web UI, alerting |
| OpenSearch | 2.15.0 | Log storage and full-text search |
| MongoDB | 7 | Graylog configuration storage |
| Docker Compose | v2+ | Container orchestration |
| Python | 3.x | Log simulation and report generation |
| rsyslog | built-in | Real SSH log forwarding |

### Why these specific versions

**Graylog 6.1 not 7.x** — Graylog 7.x had not been validated 
against OpenSearch 2.15 at time of deployment. Stability and 
documented compatibility were prioritised over running the 
latest release.

**OpenSearch not Elasticsearch** — Elastic changed its licence 
to proprietary in 2021. OpenSearch is the fully open source 
fork and is officially supported by Graylog 6.x.

**MongoDB 7** — Current stable release officially supported 
by Graylog 6.x. MongoDB stores Graylog configuration only — 
not the actual log data.

---

## Repository Structure

Catnip-Siem/ ├── docker-compose.yml # Full stack definition ├── .env.example # Environment variable template ├── .gitignore # Excludes secrets and generated files ├── bootstrap.sh # One-command automated setup ├── scripts/ │ ├── log_generator.py # Simulates Catnip Games infrastructure │ └── report_generator.py # Automated weekly security report ├── content-packs/ │ └── *.json # Graylog streams, alerts, dashboards └── docs/ ├── platform-setup.md # Infrastructure and Docker setup ├── log-ingestion.md # Inputs, extractors, streams ├── alert-rules.md # Alert definitions and remediation └── dashboards.md # Dashboard design and widget reference

---

## Prerequisites

Before you begin, make sure you have the following installed:

| Tool | Purpose | Download |
|---|---|---|
| Docker Desktop | Runs all containers | docker.com |
| Git | Clones the repository | git-scm.com |
| Python 3.x | Runs the scripts | python.org |

**Note for Windows users:** You also need WSL (Windows Subsystem 
for Linux). Open PowerShell as administrator and run:
wsl --install
Restart your computer after installation.

---

## Quick Start — Get Running in 5 Minutes

### Step 1 — Clone the repository

Open your terminal (Mac/Linux) or WSL terminal (Windows) and run:

```bash
git clone https://github.com/Captnfresh/Catnip-Siem.git
cd Catnip-Siem
Step 2 — Create your environment file
cp .env.example .env
Open .env and fill in the values. The team will share the actual values privately via WhatsApp. The file looks like this:
GRAYLOG_PASSWORD_SECRET=
GRAYLOG_ROOT_PASSWORD_SHA2=
GRAYLOG_HTTP_EXTERNAL_URI=http://localhost:9000/
OPENSEARCH_ADMIN_PASSWORD=
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
Step 3 — Run the bootstrap script
chmod +x bootstrap.sh
./bootstrap.sh
The bootstrap script automatically:
•	Detects your operating system
•	Sets the required OpenSearch kernel setting on Linux/WSL
•	Starts all three Docker containers
•	Waits for Graylog to become healthy
•	Installs Python dependencies
Expected output:
=============================================
  Catnip Games SIEM - Bootstrap
=============================================
[1/5] Checking dependencies...
[OK] Docker and Python3 found
[2/5] Configuring system settings...
[OK] vm.max_map_count set to 262144
[3/5] Checking environment configuration...
[OK] .env file found
[4/5] Starting Docker containers...
[OK] Graylog is healthy
[5/5] Installing Python dependencies...
[OK] Python dependencies installed
=============================================
  Bootstrap complete!
=============================================
Step 4 — Verify containers are running
docker compose ps
You should see all three containers with status Up:
NAME                IMAGE                                    STATUS
catnip-graylog      graylog/graylog:6.1                     Up (healthy)
catnip-mongodb      mongo:7                                  Up
catnip-opensearch   opensearchproject/opensearch:2.15.0     Up
If Graylog shows (healthy) — you are ready to proceed.
Step 5 — Access Graylog
Open your browser and go to:
http://localhost:9000
Log in with:
•	Username: admin
•	Password: shared privately with team via WhatsApp
Step 6 — Import the content pack
The content pack restores all streams, alert rules, and notifications automatically.
1.	In Graylog, click System in the top menu
2.	Click Content Packs
3.	Click Upload (top right)
4.	Select the JSON file from the content-packs/ folder
5.	Click Install
You should now see:
•	2 streams running (ssh-auth, game_server)
•	4 alert rules configured
•	Email notification set up
Step 7 — Configure rsyslog (SSH log forwarding)
This forwards real SSH logs from your machine to Graylog.
sudo apt update && sudo apt install -y rsyslog openssh-server
sudo nano /etc/rsyslog.d/60-graylog.conf
Paste this content:
# Forward auth logs (SSH) to Graylog via TCP syslog
auth,authpriv.* action(
  type="omfwd"
  target="127.0.0.1"
  port="1514"
  protocol="tcp"
)
Save with Ctrl+X, Y, Enter. Then restart rsyslog:
sudo systemctl restart rsyslog
sudo service ssh start
Step 8 — Start the log generator
The log generator simulates game server, player auth, DDoS, and SSH brute force events. This populates your dashboards with realistic data.
export GRAYLOG_PASS=your_admin_password
cd scripts
nohup python3 log_generator.py > ../logs/generator.log 2>&1 &
You should see a process ID printed. The generator runs in the background continuously.
To verify it is running:
ps aux | grep log_generator | grep -v grep
Step 9 — Verify data is flowing
Go to Graylog → Search → set time range to Last 5 minutes → click search.
You should see events arriving from catnip-simulator with fields like event_type, action, source_ip, username.
Step 10 — Generate a security report
export GRAYLOG_PASS=your_admin_password
python3 scripts/report_generator.py
The report is saved to reports/security_report_YYYY-MM-DD_HH-MM.txt and also printed to the terminal.
________________________________________
Dashboards
Five dashboards were built covering different aspects of the Catnip Games security posture:
Dashboard	Purpose	Key Widgets
Security Overview	High-level daily summary	Total events, timeline, event types, critical count
SSH Auth Monitoring	SSH brute force detection	Failed logins over time, top attacking IPs, targeted usernames
Game Server Health	DDoS and traffic monitoring	DDoS over time, targeted servers, normal vs attack traffic
Player Auth Monitoring	Credential stuffing detection	Login outcomes, targeted players, attacker IPs
Dev Environment Security	Developer server monitoring	Dev SSH activity, suspicious logins, targeted accounts
Using the Global Override: The time selector at the top of each dashboard controls all widgets simultaneously. Change it to see different time perspectives — last hour, last 24 hours, last 7 days — without editing individual widgets.
________________________________________
Alert Rules
Four automated alert rules detect the primary threats in the Catnip Games environment:
Alert 1 — SSH Brute Force Detection
•	Triggers when: A single IP generates 10+ failed SSH logins within 5 minutes
•	Why this threshold: Fewer than 10 could be a legitimate user mistyping their password. 10+ indicates automated password guessing tools.
•	Response: Block the IP, review targeted usernames, check for successful logins from same IP
Alert 2 — DDoS Attack Detected
•	Triggers when: Any single DDoS event is detected
•	Why immediate: There is no safe threshold for DDoS. Any detection event requires immediate response.
•	Response: Activate DDoS mitigation, block source IP, enable rate limiting
Alert 3 — Credential Stuffing Attack
•	Triggers when: A single IP generates 20+ credential stuffing attempts within 5 minutes
•	Why this threshold: 20 was chosen to distinguish automated tooling from normal failed login activity
•	Response: Block IP, force password reset, enable CAPTCHA
Alert 4 — Suspicious Dev SSH Login
•	Triggers when: Any suspicious login to a developer server is detected
•	Why immediate: Dev servers contain source code and deployment credentials. Any suspicious access is critical.
•	Response: Revoke access, review session, check for lateral movement
________________________________________
Log Generator — What It Simulates
Since physical access to 300 game servers is not available in this prototype, a Python script simulates the log traffic those servers would generate. This is standard practice in security engineering — synthetic log generation is used to test SIEM configurations before real infrastructure is connected.
The generator sends 8 event types via GELF to Graylog:
Event Type	Description	Severity
player_auth success	Player logged in successfully	Info
player_auth failed	Player login failed	Warning
game_traffic normal	Normal game server traffic	Info
game_traffic ddos	DDoS attack detected	Critical
dev_ssh normal	Engineer logged into dev server	Info
dev_ssh suspicious	Suspicious dev server login	Critical
player_auth credential_stuffing	Credential stuffing burst	Critical
sshd brute force	SSH brute force from attacker IP	Critical
Day/night simulation: The generator adjusts event weights based on time of day. During business hours (8am-10pm) legitimate activity dominates. At night, attack patterns increase — reflecting real-world attacker behaviour.
________________________________________
Automated Report
The report generator queries the Graylog API and produces a formatted weekly security summary covering:
•	Executive summary with overall risk level
•	SSH authentication analysis with failure rate
•	Player authentication analysis
•	Top 10 attacking IP addresses
•	Most targeted usernames
•	Most targeted game servers
•	Recent DDoS incidents with timestamps
•	Dynamic security recommendations
Risk levels are calculated automatically:
Critical Events	Risk Level
> 10,000	CRITICAL — Immediate investigation required
> 5,000	HIGH — Elevated threat activity
> 1,000	MEDIUM — Monitor closely
< 1,000	LOW — Normal activity
________________________________________
OS Compatibility
This project runs on all major operating systems with no changes to any configuration files.
Environment	Supported	Notes
Windows + WSL	Yes	Bootstrap handles kernel settings
Windows + Docker Desktop	Yes	No extra steps needed
Mac + Docker Desktop	Yes	No extra steps needed
Native Linux	Yes	Kernel setting applied once permanently
The only OS-specific step is the OpenSearch vm.max_map_count kernel setting. The bootstrap script detects the OS and handles this automatically.
________________________________________
Troubleshooting
Problem 1 — Docker Desktop stuck on "Starting the Docker Engine"
What happened: On Windows, Docker Desktop showed "Starting the Docker Engine..." indefinitely and never became ready.
What caused it: A lingering com.docker.backend.exe process from a previous session was blocking Docker Desktop from starting cleanly.
How we fixed it: When Docker Desktop showed the "Lingering processes detected" popup, we clicked "Stop processes" to kill the blocking process. Docker Desktop then started successfully within 2-3 minutes.
What it taught us: Always fully quit Docker Desktop before restarting Windows. Use the system tray icon → Quit Docker Desktop rather than just closing the window.
Alternative fix if the popup doesn't appear: Open Task Manager → find com.docker.backend.exe → End task → restart Docker Desktop.
________________________________________
Problem 2 — OpenSearch container keeps restarting
What happened: After running docker compose up -d, the OpenSearch container showed status Restarting (1) repeatedly instead of Up.
What caused it: The Linux kernel setting vm.max_map_count was too low. OpenSearch requires this to be at least 262144 to function. The default value on Linux is 65536.
How we fixed it:
sudo sysctl -w vm.max_map_count=262144
To make it permanent across reboots:
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
What it taught us: OpenSearch is not a normal application — it memory-maps large index files for performance and needs a higher virtual memory map count than the Linux default allows. This is a known requirement documented by OpenSearch and is the most common cause of OpenSearch startup failures.
________________________________________
Problem 3 — Graylog stays unhealthy and cannot reach OpenSearch
What happened: Graylog logs showed it repeatedly trying to connect to 127.0.0.1:9200 and failing with connection refused. The container status showed (unhealthy).
What caused it: Inside a Docker container, 127.0.0.1 refers to the container itself — not the host machine or other containers. Graylog was trying to reach OpenSearch on its own loopback address where nothing was listening.
How we fixed it: Changed the OpenSearch connection string in docker-compose.yml to use the Docker service name instead:
GRAYLOG_ELASTICSEARCH_HOSTS=http://opensearch:9200
Docker's internal DNS resolves service names to the correct container IP automatically on the catnip-net network.
What it taught us: Docker containers communicate using service names defined in docker-compose.yml, not IP addresses or localhost. This is a fundamental Docker networking concept that affects every multi-container deployment.
________________________________________
Problem 4 — SSH extractor showing mixed case values
What happened: The action field in Graylog was showing both Failed (capital F from real rsyslog messages) and failed (lowercase from GELF generator messages). Dashboard widgets showed duplicate legend entries and queries using action:failed missed real SSH events.
What caused it: Real SSH log messages from rsyslog use title case — "Failed password", "Accepted password". The Python generator used lowercase consistently. The extractor regex captured the value as-is without normalising the case.
How we fixed it: Updated the extract_action extractor regex to use a case-insensitive flag and added a Lowercase string converter:
Regex: (?i)(failed|accepted|invalid)
Converter: Lowercase string
This normalises all new incoming values to lowercase. Historical capitalised values remain in OpenSearch but fade out over time as new normalised events replace them.
What it taught us: Log normalisation is critical in a SIEM. When logs come from multiple sources — real systems and simulated ones — inconsistencies in field values break queries and dashboards. Extractors should always normalise to a consistent format.
________________________________________
Problem 5 — GitHub push rejected due to email privacy
What happened: Running git push returned an error:
remote: error: GH007: Your push would publish a private 
email address.
What caused it: GitHub's email privacy protection was enabled on the account. The git config had a real email address that GitHub refused to expose publicly in commit history.
How we fixed it: Two options — either make the email public in GitHub Settings, or use the GitHub no-reply email address:
git config --global user.email "username@users.noreply.github.com"
git commit --amend --reset-author --no-edit
git push
What it taught us: GitHub provides a no-reply email address specifically for this purpose. Using it keeps personal email addresses private while still allowing commits to be attributed correctly.
________________________________________
Problem 6 — Team member could not push to repository
What happened: A team member ran git push and received authentication errors despite entering their GitHub password correctly.
Two separate issues occurred:
Issue A — Collaborator invitation not accepted: The team member had not accepted the GitHub collaborator invitation sent to their email. GitHub requires explicit acceptance before granting push access to a repository.
Fix: Check email for invitation from GitHub, click Accept, then retry the push.
Issue B — Personal Access Token missing repo scope: After accepting the invitation, the team member generated a Personal Access Token but did not tick the repo checkbox when creating it. A token without repo scope cannot push to repositories.
Fix: Generate a new token at: GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic) → Generate new token
Make sure to tick repo — this grants full repository access. Copy the token immediately as GitHub only shows it once. Use this token as the password when Git prompts for credentials.
What it taught us: GitHub removed password authentication for Git operations in 2021. Personal Access Tokens are now required. The scope selection when creating the token is critical — a token without the right scope is silently useless.
________________________________________
Restarting After a Break
If you close your laptop or restart WSL, run these commands to get everything back up:
# Start Docker containers
cd ~/catnip-siem
docker compose up -d

# Verify all containers are healthy
docker compose ps

# Restart the log generator
export GRAYLOG_PASS=your_admin_password
cd scripts
nohup python3 log_generator.py > ../logs/generator.log 2>&1 &

# Access Graylog
# Open browser → http://localhost:9000
________________________________________
Project Team
Name	Role	Contribution
Adebowale (Team Lead)	Architecture & Python	Docker infrastructure, log generator, report script, project coordination
Steven	UI Platform	Graylog platform deployment and maintenance
Lekan	Log Ingestion	Inputs, extractors, rsyslog configuration, streams
Faith	Alerts	Event definitions, notifications, remediation procedures
Sky	Dashboards	5 dashboards, 20 widgets, visualisation design
Chamberlain	Documentation	README, process documentation, GitHub repo structure
________________________________________
Known Limitations
Log count cap: The Graylog API returns a maximum of 10,000 messages per query. Event counts in the automated report that show exactly 10,000 are likely higher in reality. This is a Graylog API constraint.
Simulated infrastructure: The Python log generator replaces real game server infrastructure. In a production deployment, rsyslog agents on each of the 300 game servers would replace the generator. The log formats and field structures are identical — only the source changes.
Single node deployment: This deployment runs on a single machine with no high availability or failover. The brief mentions 99.9% uptime as a requirement — achieving this in production would require a multi-node OpenSearch cluster and Graylog cluster configuration beyond the scope of this prototype.
Data retention: No explicit data retention policy has been configured. OpenSearch default retention applies. In production, a 30-day hot storage policy would be configured as specified in the brief.
________________________________________
Module Context
Built for the Cyber Security Automation module at the University of Roehampton.
Scenario: Catnip Games International SIEM implementation
Work Role: DCWF 511 — Cyber Defense Analyst
Competency: Uses data collected from cyber defense tools to analyse events for the purposes of mitigating threats.
Assessment: In-lab team demonstration with individual Q&A


