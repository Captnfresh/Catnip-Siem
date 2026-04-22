/**
 * PrintReport — pure modal component.
 * The trigger button and time-range state live in TopBar.tsx.
 *
 * Printing opens a NEW, clean browser window containing only the report
 * rendered as self-contained HTML + inline CSS. This guarantees the
 * printed output matches the preview — no dark overlay, no Tailwind
 * class resolution issues, no fixed-position modal chrome.
 */
import { X, Printer, Loader2, AlertTriangle, ShieldCheck } from "lucide-react";
import type { ReportData } from "@/lib/api";

// ---------------------------------------------------------------------------
// Colour helpers (used in both the modal preview and the print HTML)
// ---------------------------------------------------------------------------

const LEVEL_COLOUR: Record<string, string> = {
  Critical: "text-red-400 border-red-400/30 bg-red-400/10",
  High:     "text-orange-400 border-orange-400/30 bg-orange-400/10",
  Medium:   "text-yellow-400 border-yellow-400/30 bg-yellow-400/10",
  Low:      "text-blue-400 border-blue-400/30 bg-blue-400/10",
};

const LEVEL_PRINT_BG: Record<string, string> = {
  Critical: "#7f1d1d",
  High:     "#7c2d12",
  Medium:   "#713f12",
  Low:      "#1e3a5f",
};

const LEVEL_PRINT_FG: Record<string, string> = {
  Critical: "#fca5a5",
  High:     "#fdba74",
  Medium:   "#fde047",
  Low:      "#93c5fd",
};

function fmt(ts: string) {
  if (!ts) return "—";
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

function fmtShort(ts: string) {
  if (!ts) return "—";
  try { return new Date(ts).toLocaleString(undefined, { dateStyle: "short", timeStyle: "short" }); }
  catch { return ts; }
}

// ---------------------------------------------------------------------------
// Generate self-contained print HTML
// ---------------------------------------------------------------------------

function generatePrintHtml(report: ReportData): string {
  const badge = (level: string) =>
    `<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;font-family:monospace;background:${LEVEL_PRINT_BG[level] ?? "#333"};color:${LEVEL_PRINT_FG[level] ?? "#ccc"}">${level}</span>`;

  const categoriesHtml = report.categories
    .filter(c => c.count > 0)
    .map(cat => `
      <div style="border:1px solid #334155;border-radius:6px;padding:16px;margin-bottom:16px;break-inside:avoid">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
          <span style="font-weight:700;font-size:14px">${cat.label} — ${cat.dominant_threat} ${badge(cat.severity)}</span>
          <span style="font-family:monospace;font-weight:700;font-size:14px">${cat.count.toLocaleString()} events</span>
        </div>
        <p style="color:#94a3b8;font-size:12px;margin:0 0 8px 0">${cat.description}</p>
        ${cat.threat_breakdown && cat.threat_breakdown.length > 1 ? `
          <div style="margin-bottom:8px">
            <span style="font-size:11px;color:#64748b;font-family:monospace">BREAKDOWN: </span>
            ${cat.threat_breakdown.map(t => `<span style="font-size:11px;font-family:monospace;background:#1e293b;padding:2px 6px;border-radius:3px;margin-right:4px">${t.name} ×${t.count}</span>`).join("")}
          </div>
        ` : ""}
        ${cat.sample_events.length > 0 ? `
          <div>
            <div style="font-size:11px;color:#64748b;font-family:monospace;margin-bottom:4px">SAMPLE EVENTS</div>
            ${cat.sample_events.slice(0, 5).map(e => `
              <div style="font-family:monospace;font-size:11px;background:#0f172a;padding:4px 8px;border-radius:3px;margin-bottom:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
                <span style="color:#64748b">${fmtShort(e.timestamp)}</span>
                <span style="color:#334155;margin:0 4px">|</span>
                <span style="color:#94a3b8">${e.source}</span>
                <span style="color:#334155;margin:0 4px">|</span>
                <span style="color:#cbd5e1">${e.message}</span>
              </div>`).join("")}
          </div>
        ` : ""}
      </div>`).join("");

  const cvesHtml = report.cve_mappings.length > 0 ? `
    <table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:12px">
      <thead>
        <tr style="border-bottom:2px solid #334155;color:#64748b">
          <th style="text-align:left;padding:8px 12px 8px 0">CVE ID</th>
          <th style="text-align:left;padding:8px 12px 8px 0">CVSS</th>
          <th style="text-align:left;padding:8px 12px 8px 0">Threat</th>
          <th style="text-align:left;padding:8px 0">Description</th>
        </tr>
      </thead>
      <tbody>
        ${report.cve_mappings.map(c => {
          const cvssColor = c.cvss == null ? "#94a3b8" : c.cvss >= 9 ? "#f87171" : c.cvss >= 7 ? "#fb923c" : "#fde047";
          return `<tr style="border-bottom:1px solid #1e293b">
            <td style="padding:6px 12px 6px 0;color:#f87171;font-weight:700">${c.id}</td>
            <td style="padding:6px 12px 6px 0;color:${cvssColor};font-weight:700">${c.cvss != null ? c.cvss.toFixed(1) : "—"}</td>
            <td style="padding:6px 12px 6px 0;color:#94a3b8">${c.related_threat ?? ""}</td>
            <td style="padding:6px 0;color:#cbd5e1">${c.description}</td>
          </tr>`;
        }).join("")}
      </tbody>
    </table>` : "<p style='color:#64748b;font-size:12px'>No CVEs mapped for this time window.</p>";

  const remediationHtml = report.remediation_plan.map((item, idx) => `
    <div style="border:1px solid #334155;border-radius:6px;padding:16px;margin-bottom:12px;break-inside:avoid">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;flex-wrap:wrap">
        <span style="font-family:monospace;font-size:11px;background:#1e293b;padding:2px 6px;border-radius:3px;color:#94a3b8">Priority ${idx + 1}</span>
        <span style="font-weight:700;font-size:13px">${item.threat}</span>
        ${badge(item.severity)}
        <span style="margin-left:auto;font-family:monospace;font-size:11px;color:#64748b">${item.count.toLocaleString()} events</span>
      </div>
      <ol style="margin:0;padding-left:20px;color:#94a3b8;font-size:12px">
        ${item.steps.map(s => `<li style="margin-bottom:4px">${s}</li>`).join("")}
      </ol>
    </div>`).join("");

  const sourcesHtml = report.top_sources.slice(0, 10).map(s =>
    `<div style="display:flex;justify-content:space-between;font-family:monospace;font-size:12px;padding:4px 8px;background:#0f172a;border-radius:3px;margin-bottom:3px">
      <span style="color:#cbd5e1">${s.source}</span>
      <span style="color:#f8fafc;font-weight:700">${s.event_count}</span>
    </div>`).join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>OmniLog Security Report — ${report.period}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #0f172a;
      color: #f8fafc;
      padding: 32px;
      font-size: 13px;
      line-height: 1.5;
    }
    h2 {
      font-family: monospace;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: #94a3b8;
      border-bottom: 1px solid #334155;
      padding-bottom: 6px;
      margin-bottom: 16px;
      margin-top: 32px;
    }
    h2:first-of-type { margin-top: 0; }
    @media print {
      body { background: #fff !important; color: #000 !important; padding: 16px; }
      * { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
    }
  </style>
</head>
<body>
  <!-- Report header -->
  <div style="border-bottom:2px solid #334155;padding-bottom:20px;margin-bottom:24px">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
      <span style="font-size:20px;font-weight:800;font-family:monospace">Catnip Games — OmniLog Security Report</span>
    </div>
    <div style="display:flex;gap:24px;font-family:monospace;font-size:12px;color:#94a3b8;flex-wrap:wrap">
      <span>Generated: ${fmt(report.generated_at)}</span>
      <span>Period: ${report.period}</span>
      <span>${badge(report.overall_threat_level)} Overall Threat Level</span>
    </div>
  </div>

  <!-- Executive Summary -->
  <h2>Executive Summary</h2>
  <p style="color:#cbd5e1;font-size:13px;line-height:1.7;margin-bottom:24px">${report.executive_summary}</p>

  <!-- Statistics -->
  <h2>Key Statistics</h2>
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px">
    ${[
      ["Total Events",     report.statistics.total_events.toLocaleString()],
      ["Failed Logins",    report.statistics.failed_logins.toLocaleString()],
      ["Suspicious",       report.statistics.suspicious_events.toLocaleString()],
      ["Unique Sources",   report.statistics.unique_sources.toLocaleString()],
    ].map(([label, val]) => `
      <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:14px;text-align:center">
        <div style="font-size:22px;font-weight:800;font-family:monospace;color:#f8fafc">${val}</div>
        <div style="font-size:11px;color:#64748b;margin-top:4px">${label}</div>
      </div>`).join("")}
  </div>

  <!-- ML Engine -->
  <h2>ML Anomaly Engine</h2>
  <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:16px;margin-bottom:24px">
    ${report.ml_analysis.status === "active" ? `
      <div style="display:flex;gap:32px;font-family:monospace;font-size:12px;flex-wrap:wrap">
        <div><div style="color:#64748b;font-size:11px">STATUS</div><div style="color:#4ade80;font-weight:700">ACTIVE</div></div>
        <div><div style="color:#64748b;font-size:11px">EVENTS SCORED</div><div style="font-weight:700">${report.ml_analysis.events_scored ?? 0}</div></div>
        <div><div style="color:#64748b;font-size:11px">ZERO-DAY ANOMALIES</div><div style="color:${(report.ml_analysis.zero_day_count ?? 0) > 0 ? "#f87171" : "#f8fafc"};font-weight:700">${report.ml_analysis.zero_day_count ?? 0}</div></div>
        <div><div style="color:#64748b;font-size:11px">HIGH-RISK DETECTIONS</div><div style="color:${(report.ml_analysis.high_risk_count ?? 0) > 0 ? "#fb923c" : "#f8fafc"};font-weight:700">${report.ml_analysis.high_risk_count ?? 0}</div></div>
        <div><div style="color:#64748b;font-size:11px">ANOMALY RATE</div><div style="font-weight:700">${(((report.ml_analysis.anomaly_rate ?? 0)) * 100).toFixed(1)}%</div></div>
      </div>` : `<p style="color:#64748b;font-size:12px">ML service unavailable during report generation.</p>`}
  </div>

  <!-- Threat Category Breakdown -->
  <h2>Threat Category Breakdown</h2>
  <div style="margin-bottom:24px">${categoriesHtml}</div>

  <!-- CVE Correlation -->
  <h2>CVE Correlation</h2>
  <div style="margin-bottom:24px">${cvesHtml}</div>

  <!-- Remediation Plan -->
  <h2>Prioritised Remediation Plan</h2>
  <div style="margin-bottom:24px">${remediationHtml || "<p style='color:#64748b;font-size:12px'>No remediation items for this window.</p>"}</div>

  <!-- Top Sources -->
  ${report.top_sources.length > 0 ? `
  <h2>Top Event Sources</h2>
  <div style="columns:2;gap:8px;margin-bottom:24px">${sourcesHtml}</div>` : ""}

  <!-- Footer -->
  <div style="border-top:1px solid #334155;padding-top:12px;font-family:monospace;font-size:11px;color:#475569;display:flex;justify-content:space-between;flex-wrap:wrap;gap:4px">
    <span>OmniLog v1.0 · Catnip Games SIEM · Confidential</span>
    <span>${fmt(report.generated_at)}</span>
  </div>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface PrintReportProps {
  isOpen:  boolean;
  onClose: () => void;
  loading: boolean;
  error:   string | null;
  report:  ReportData | null;
}

export default function PrintReport({ isOpen, onClose, loading, error, report }: PrintReportProps) {
  if (!isOpen) return null;

  const handlePrint = () => {
    if (!report) return;
    const win = window.open("", "_blank", "width=900,height=700");
    if (!win) {
      alert("Please allow pop-ups for this site to print the report.");
      return;
    }
    win.document.write(generatePrintHtml(report));
    win.document.close();
    win.focus();
    // Small delay so the browser finishes rendering before print dialog
    setTimeout(() => win.print(), 400);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/80 overflow-y-auto p-4">
      <div className="bg-background border border-border rounded-lg w-full max-w-5xl my-4">

        {/* Toolbar */}
        <div className="flex items-center justify-between p-4 border-b border-border sticky top-0 bg-background z-10">
          <div className="flex items-center gap-2">
            <span className="font-mono font-semibold text-sm text-foreground">Security Report</span>
            {report && (
              <span className="text-xs font-mono text-muted-foreground">— {report.period}</span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handlePrint}
              disabled={!report}
              className="flex items-center gap-1.5 text-xs font-mono text-accent border border-accent/30 hover:bg-accent/10 disabled:opacity-40 px-3 py-1.5 rounded transition-colors"
            >
              <Printer className="h-3.5 w-3.5" /> Print / Save PDF
            </button>
            <button onClick={onClose} className="text-muted-foreground hover:text-foreground p-1">
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Modal body */}
        <div className="p-6 space-y-8">

          {loading && (
            <div className="flex items-center justify-center py-24 gap-3 text-muted-foreground">
              <Loader2 className="h-5 w-5 animate-spin" />
              <span className="font-mono text-sm">Scanning logs — this may take up to 30 seconds…</span>
            </div>
          )}

          {error && !loading && (
            <div className="flex items-center gap-2 text-destructive font-mono text-sm p-4 border border-destructive/30 rounded">
              <AlertTriangle className="h-4 w-4 flex-shrink-0" />
              {error}
            </div>
          )}

          {report && !loading && (
            <>
              {/* Report header */}
              <div className="border-b border-border pb-6">
                <h1 className="text-2xl font-bold font-mono text-foreground">
                  Catnip Games — OmniLog Security Report
                </h1>
                <div className="flex flex-wrap items-center gap-4 mt-2 text-xs text-muted-foreground font-mono">
                  <span>Generated: {fmt(report.generated_at)}</span>
                  <span>Period: {report.period}</span>
                  <span className={`px-2 py-0.5 rounded border font-medium ${LEVEL_COLOUR[report.overall_threat_level] ?? ""}`}>
                    Overall Threat: {report.overall_threat_level}
                  </span>
                </div>
              </div>

              {/* Executive Summary */}
              <section>
                <h2 className="text-xs font-bold font-mono text-foreground uppercase tracking-wider mb-3 pb-1.5 border-b border-border">
                  Executive Summary
                </h2>
                <p className="text-sm text-muted-foreground leading-relaxed">{report.executive_summary}</p>
              </section>

              {/* Statistics */}
              <section>
                <h2 className="text-xs font-bold font-mono text-foreground uppercase tracking-wider mb-3 pb-1.5 border-b border-border">
                  Key Statistics
                </h2>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {[
                    { label: "Total Events",     value: report.statistics.total_events.toLocaleString() },
                    { label: "Failed Logins",    value: report.statistics.failed_logins.toLocaleString() },
                    { label: "Suspicious",       value: report.statistics.suspicious_events.toLocaleString() },
                    { label: "Unique Sources",   value: report.statistics.unique_sources.toLocaleString() },
                  ].map(s => (
                    <div key={s.label} className="p-4 rounded border border-border bg-muted/30 text-center">
                      <div className="text-2xl font-bold font-mono text-foreground">{s.value}</div>
                      <div className="text-xs text-muted-foreground mt-1">{s.label}</div>
                    </div>
                  ))}
                </div>
              </section>

              {/* ML Analysis */}
              <section>
                <h2 className="text-xs font-bold font-mono text-foreground uppercase tracking-wider mb-3 pb-1.5 border-b border-border">
                  ML Anomaly Engine
                </h2>
                {report.ml_analysis.status === "active" ? (
                  <div className="p-4 rounded border border-border bg-muted/20">
                    <div className="flex items-center gap-2 mb-3">
                      <ShieldCheck className="h-4 w-4 text-accent" />
                      <span className="text-sm font-mono text-accent font-medium">Engine Active</span>
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-sm font-mono">
                      {[
                        { label: "Events Scored",       value: String(report.ml_analysis.events_scored ?? 0),   colour: "" },
                        { label: "Zero-Day Anomalies",  value: String(report.ml_analysis.zero_day_count ?? 0),  colour: (report.ml_analysis.zero_day_count ?? 0) > 0 ? "text-destructive" : "" },
                        { label: "High-Risk",           value: String(report.ml_analysis.high_risk_count ?? 0), colour: (report.ml_analysis.high_risk_count ?? 0) > 0 ? "text-orange-400" : "" },
                        { label: "Anomaly Rate",        value: `${(((report.ml_analysis.anomaly_rate ?? 0)) * 100).toFixed(1)}%`, colour: "" },
                      ].map(s => (
                        <div key={s.label}>
                          <div className="text-muted-foreground text-xs">{s.label}</div>
                          <div className={`font-bold text-foreground ${s.colour}`}>{s.value}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">ML service unavailable.</p>
                )}
              </section>

              {/* Threat Categories */}
              <section>
                <h2 className="text-xs font-bold font-mono text-foreground uppercase tracking-wider mb-3 pb-1.5 border-b border-border">
                  Threat Category Breakdown
                </h2>
                <div className="space-y-4">
                  {report.categories.map(cat => (
                    <div key={cat.key} className="border border-border rounded-lg p-4">
                      <div className="flex items-start justify-between mb-2 gap-2">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-mono font-semibold text-foreground">{cat.label}</span>
                          <span className={`text-xs px-2 py-0.5 rounded border ${LEVEL_COLOUR[cat.severity] ?? ""}`}>{cat.severity}</span>
                        </div>
                        <span className="font-mono font-bold text-foreground flex-shrink-0">{cat.count.toLocaleString()} events</span>
                      </div>
                      <p className="text-xs text-muted-foreground mb-2">
                        <span className="text-foreground font-medium">Dominant: </span>
                        {cat.dominant_threat} — {cat.description}
                      </p>
                      {cat.threat_breakdown && cat.threat_breakdown.length > 1 && (
                        <div className="mb-2 flex flex-wrap gap-1.5">
                          {cat.threat_breakdown.map(t => (
                            <span key={t.name} className="text-xs font-mono bg-muted/40 border border-border rounded px-2 py-0.5">
                              {t.name} <span className="text-primary font-bold">×{t.count}</span>
                            </span>
                          ))}
                        </div>
                      )}
                      {cat.sample_events.length > 0 && (
                        <div className="space-y-1 max-h-40 overflow-y-auto">
                          {cat.sample_events.map((e, i) => (
                            <div key={i} className="text-xs font-mono bg-muted/30 rounded px-2 py-1 flex gap-2 min-w-0">
                              <span className="text-muted-foreground flex-shrink-0">{fmtShort(e.timestamp)}</span>
                              <span className="text-border flex-shrink-0">|</span>
                              <span className="text-foreground/80 flex-shrink-0">{e.source}</span>
                              <span className="text-border flex-shrink-0">|</span>
                              <span className="truncate">{e.message}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </section>

              {/* CVE Correlation */}
              {report.cve_mappings.length > 0 && (
                <section>
                  <h2 className="text-xs font-bold font-mono text-foreground uppercase tracking-wider mb-3 pb-1.5 border-b border-border">
                    CVE Correlation
                  </h2>
                  <div className="overflow-x-auto border border-border rounded-lg">
                    <table className="w-full text-xs font-mono">
                      <thead className="border-b border-border bg-muted/30">
                        <tr className="text-muted-foreground text-left">
                          <th className="p-3 pr-4">CVE ID</th>
                          <th className="p-3 pr-4">CVSS</th>
                          <th className="p-3 pr-4">Related Threat</th>
                          <th className="p-3">Description</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border/50">
                        {report.cve_mappings.map(cve => (
                          <tr key={cve.id} className="hover:bg-muted/20">
                            <td className="p-3 pr-4 text-destructive font-semibold whitespace-nowrap">{cve.id}</td>
                            <td className="p-3 pr-4 whitespace-nowrap">
                              {cve.cvss != null ? (
                                <span className={cve.cvss >= 9 ? "text-red-400 font-bold" : cve.cvss >= 7 ? "text-orange-400 font-bold" : "text-yellow-400"}>
                                  {cve.cvss.toFixed(1)}
                                </span>
                              ) : "—"}
                            </td>
                            <td className="p-3 pr-4 text-muted-foreground whitespace-nowrap">{cve.related_threat}</td>
                            <td className="p-3 text-foreground/70">{cve.description}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              )}

              {/* Remediation Plan */}
              {report.remediation_plan.length > 0 && (
                <section>
                  <h2 className="text-xs font-bold font-mono text-foreground uppercase tracking-wider mb-3 pb-1.5 border-b border-border">
                    Prioritised Remediation Plan
                  </h2>
                  <div className="space-y-4">
                    {report.remediation_plan.map((item, idx) => (
                      <div key={idx} className="border border-border rounded-lg p-4">
                        <div className="flex items-center gap-2 mb-3 flex-wrap">
                          <span className="text-xs font-mono text-muted-foreground bg-muted px-2 py-0.5 rounded">Priority {idx + 1}</span>
                          <span className="font-mono font-semibold text-foreground">{item.threat}</span>
                          <span className={`text-xs px-2 py-0.5 rounded border ${LEVEL_COLOUR[item.severity] ?? ""}`}>{item.severity}</span>
                          <span className="ml-auto text-xs text-muted-foreground font-mono">{item.count.toLocaleString()} events</span>
                        </div>
                        <ol className="space-y-1.5">
                          {item.steps.map((step, si) => (
                            <li key={si} className="flex gap-2.5 text-sm">
                              <span className="text-primary font-mono font-bold flex-shrink-0 mt-0.5">{si + 1}.</span>
                              <span className="text-muted-foreground">{step}</span>
                            </li>
                          ))}
                        </ol>
                      </div>
                    ))}
                  </div>
                </section>
              )}

              {/* Top Sources */}
              {report.top_sources.length > 0 && (
                <section>
                  <h2 className="text-xs font-bold font-mono text-foreground uppercase tracking-wider mb-3 pb-1.5 border-b border-border">
                    Top Event Sources
                  </h2>
                  <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-2">
                    {report.top_sources.map(s => (
                      <div key={s.source} className="flex items-center justify-between text-xs font-mono p-2 rounded border border-border bg-muted/20">
                        <span className="text-foreground/80 truncate">{s.source}</span>
                        <span className="ml-2 font-bold text-foreground flex-shrink-0">{s.event_count}</span>
                      </div>
                    ))}
                  </div>
                </section>
              )}

              {/* Footer */}
              <div className="border-t border-border pt-4 text-xs text-muted-foreground font-mono flex justify-between flex-wrap gap-2">
                <span>OmniLog v1.0 · Catnip Games SIEM · Confidential</span>
                <span>{fmt(report.generated_at)}</span>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
