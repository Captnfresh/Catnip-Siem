# OmniLog — AI-Powered Log Analysis UI

React + TypeScript frontend for the Catnip Games SIEM. Provides a conversational interface powered by Claude to query and analyse Graylog security logs in natural language.

## Stack

- React 18 + TypeScript + Vite
- Tailwind CSS + shadcn/ui components
- React Query for data fetching
- Recharts for threat visualisation

## Running

The bootstrap script (`bootstrap.ps1` / `bootstrap.sh`) starts everything automatically. To run the frontend manually:

```bash
cd omnilog
npm install
npm run dev
```

Runs on **http://localhost:5173**. Requires the OmniLog API (port 5002) to be running.

## Dependencies

Use **npm** (not bun) to match the bootstrap scripts.

## Architecture

```
Browser (port 5173)
  └─ Vite dev server proxies /omnilog-api → http://localhost:5002
       └─ OmniLog API (Flask, scripts/omnilog_api.py)
            ├─ Claude claude-opus-4-7 — natural language threat analysis
            ├─ Graylog REST API — log retrieval
            └─ ML Service (port 5001) — severity scoring
```

## Environment

The API backend reads from the project root `.env` file. Set `ANTHROPIC_API_KEY` for Claude integration.
