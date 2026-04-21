/**
 * OmniLog API client — calls the Flask backend at /omnilog-api
 * which is proxied by Vite (dev) or nginx (prod) to port 5002.
 *
 * Falls back to generateMockAnalysis() when the backend is unreachable,
 * so the UI stays usable during frontend-only development.
 */

import { type ThreatAnalysis, generateMockAnalysis } from "./mock-logs";

const BASE = "/omnilog-api";

export interface StatusResponse {
  graylog_connected: boolean;
  ml_service_connected: boolean;
  claude_enabled?: boolean;
  active_alerts: number;
  risk_score: number;
  total_events_last_hour: number;
}

export async function fetchStatus(): Promise<StatusResponse> {
  const res = await fetch(`${BASE}/status`, { signal: AbortSignal.timeout(3000) });
  if (!res.ok) throw new Error(`Status ${res.status}`);
  return res.json();
}

export async function fetchAnalysis(
  query: string,
  sessionId?: string,
): Promise<ThreatAnalysis> {
  try {
    const res = await fetch(`${BASE}/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query, sessionId: sessionId ?? null }),
      signal: AbortSignal.timeout(60000), // Claude tool loops can take up to ~60s
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  } catch {
    // Backend unavailable — fall back to mock so UI stays functional
    return generateMockAnalysis(query);
  }
}

export async function clearSession(sessionId: string): Promise<void> {
  try {
    await fetch(`${BASE}/chat/session/${sessionId}`, { method: "DELETE" });
  } catch {
    // ignore
  }
}
