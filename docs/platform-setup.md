# Platform Setup — Graylog SIEM Infrastructure

**Contributor:** Stephen Ajayi  
**Role:** UI Platform Setup and Maintenance  
**Project:** Catnip Games International SIEM  

---

## Overview

My responsibility in this project was deploying and maintaining the 
Graylog SIEM platform — ensuring the infrastructure was running 
correctly, accessible to the team, and stable throughout development.

This covers the Docker-based deployment of three core services:
- **Graylog 6.1** — the SIEM brain and web interface
- **OpenSearch 2.15.0** — log storage and search engine
- **MongoDB 7** — configuration and metadata storage

---

## Architecture Decision

I chose Docker Compose for deployment because it allowed the entire 
stack to be defined in a single file and started with one command. 
This made the platform reproducible across all team members' machines 
regardless of operating system.

I chose **Graylog 6.1** over the newer 7.x release deliberately — 
Graylog 7.x had not been fully validated against OpenSearch 2.15 at 
the time of deployment. Stability and documented compatibility were 
prioritised over running the latest release.

I chose **OpenSearch** over Elasticsearch because Elasticsearch 
changed its licence in 2021 to a proprietary model. OpenSearch is 
the fully open source fork and is officially recommended by Graylog 
6.x documentation.

---

## Infrastructure Components

### Docker Compose Stack

Three containers run on a private Docker network called `catnip-net`:

| Container | Image | Purpose |
|---|---|---|
| catnip-graylog | graylog/graylog:6.1 | SIEM application + web UI |
| catnip-opensearch | opensearchproject/opensearch:2.15.0 | Log storage + search |
| catnip-mongodb | mongo:7 | Configuration storage |

### Port Mapping

| Port | Protocol | Purpose |
|---|---|---|
| 9000 | TCP | Graylog web interface |
| 1514 | TCP | Syslog TCP input |
| 1514 | UDP | Syslog UDP input |
| 12201 | UDP | GELF UDP input |

### Persistent Volumes

Three Docker volumes persist data across container restarts:
- `mongodb_data` — Graylog configuration, dashboards, alert rules
- `opensearch_data` — all indexed log messages
- `graylog_data` — Graylog application data

---

## Security Configuration

### Secret Management

All sensitive values are stored in a `.env` file that is never 
committed to GitHub. The `.gitignore` explicitly excludes `.env`.

The `.env.example` file documents required variables with empty 
values and a note that actual values are shared privately with the 
team.

### Password Hashing

Graylog requires the admin password stored as a SHA-256 hash — 
never plain text. Generated using:

```bash
echo -n "your_password" | sha256sum | cut -d' ' -f1
```

### SMTP Email

Email alerting is configured via Gmail SMTP environment variables 
in `docker-compose.yml`. A Gmail App Password is required — 
standard Gmail passwords are rejected by Google for third-party 
applications.

---

## Deployment Steps

### Prerequisites
- Docker installed and running
- Git installed

### 1. Clone the repository
```bash
git clone https://github.com/Captnfresh/Catnip-Siem.git
cd Catnip-Siem
```

### 2. Configure environment
```bash
cp .env.example .env
# Fill in values — shared privately with team
```

### 3. Start the platform
```bash
docker compose up -d
```

### 4. Verify deployment
```bash
docker compose ps
```

Expected output — all three containers showing `Up` and Graylog 
showing `(healthy)`.

### 5. Access Graylog UI
Open browser and navigate to `http://localhost:9000`

---

## Troubleshooting

### Docker Desktop stuck on "Starting the Docker Engine"
This was encountered during development on Windows. Resolution:
1. Click "Stop processes" when prompted about lingering processes
2. Allow Docker Desktop 2-3 minutes to fully initialise
3. Look for "Engine running" indicator at bottom left before proceeding

### OpenSearch requires vm.max_map_count
OpenSearch needs a higher virtual memory map count than the Linux 
default. On WSL this resets on restart — set it manually with:

```bash
sudo sysctl -w vm.max_map_count=262144
```

On Mac with Docker Desktop, this is not required.

### Graylog notification: "outdated version"
Graylog 7.0.6 was released after our deployment. We deliberately 
remained on 6.1 for compatibility reasons — this notification can 
be dismissed.

---

## Platform Maintenance

During the project I was responsible for:
- Verifying all three containers remained healthy throughout development
- Monitoring the Graylog System Overview page for notifications
- Confirming port mappings were correct after Docker restarts
- Ensuring the Graylog web interface was accessible to all team members
- Documenting the Docker configuration for reproducibility

---

## Key Learning

The most significant challenge was understanding the relationship 
between Docker containers on a private network. Graylog cannot reach 
OpenSearch via `127.0.0.1` (which refers to the container itself) — 
it must use the Docker service name `opensearch` which resolves to 
the correct internal IP on the `catnip-net` network. This was a 
critical configuration decision that took debugging to resolve.
