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

// ---------------------------------------------------------------------------
// Dashboard counts
// ---------------------------------------------------------------------------

export interface DashboardEvent {
  timestamp: string;
  source: string;
  message: string;
  severity: string;
  action: string;
  event_type: string;
  threat_name: string;
}

export interface DashboardCategory {
  count: number;
  label: string;
  events: DashboardEvent[];
}

export interface DashboardCounts {
  failed_logins:       DashboardCategory;
  errors:              DashboardCategory;
  network_activity:    DashboardCategory;
  suspicious_behaviour: DashboardCategory;
}

export async function fetchDashboardCounts(): Promise<DashboardCounts> {
  const res = await fetch(`${BASE}/dashboard-counts`, {
    signal: AbortSignal.timeout(15000),
  });
  if (!res.ok) throw new Error(`Status ${res.status}`);
  return res.json();
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

export interface ReportCve {
  id: string;
  description: string;
  cvss: number | null;
  related_threat?: string;
}

export interface ReportCategory {
  key: string;
  label: string;
  count: number;
  dominant_threat: string;
  severity: string;
  description: string;
  cves: ReportCve[];
  remediation: string[];
  sample_events: DashboardEvent[];
}

export interface RemediationItem {
  threat: string;
  severity: string;
  count: number;
  steps: string[];
}

export interface ReportData {
  generated_at: string;
  period: string;
  overall_threat_level: string;
  executive_summary: string;
  statistics: {
    total_events: number;
    failed_logins: number;
    suspicious_events: number;
    unique_sources: number;
  };
  categories: ReportCategory[];
  ml_analysis: {
    status: string;
    events_scored?: number;
    zero_day_count?: number;
    high_risk_count?: number;
    anomaly_rate?: number;
  };
  cve_mappings: ReportCve[];
  remediation_plan: RemediationItem[];
  top_sources: { source: string; event_count: number }[];
}

export async function fetchReport(): Promise<ReportData> {
  const res = await fetch(`${BASE}/report`, {
    signal: AbortSignal.timeout(30000),
  });
  if (!res.ok) throw new Error(`Status ${res.status}`);
  return res.json();
}

// ---------------------------------------------------------------------------
// Zero-day alerts
// ---------------------------------------------------------------------------

export interface ZeroDayThreat {
  id: string;
  timestamp: string;
  source: string;
  message: string;
  zero_day_score: number;
  combined_risk: number;
  ml_severity: string;
  attack_type: string;
  description: string;
  is_zero_day: boolean;
  cves: ReportCve[];
  remediation: string[];
}

export interface ZeroDayAlertsResponse {
  total_scanned: number;
  zero_day_count: number;
  model_trained: boolean;
  threats: ZeroDayThreat[];
}

export async function fetchZeroDayAlerts(): Promise<ZeroDayAlertsResponse> {
  const res = await fetch(`${BASE}/zero-day-alerts`, {
    signal: AbortSignal.timeout(35000),
  });
  if (!res.ok) throw new Error(`Status ${res.status}`);
  return res.json();
}

export async function clearSession(sessionId: string): Promise<void> {
  try {
    await fetch(`${BASE}/chat/session/${sessionId}`, { method: "DELETE" });
  } catch {
    // ignore
  }
}
