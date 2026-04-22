/**
 * PrintReport — pure modal component.
 * The trigger button and time-range state live in TopBar.tsx.
 */
import { X, Printer, Loader2, AlertTriangle, ShieldCheck } from "lucide-react";
import type { ReportData } from "@/lib/api";

const LEVEL_COLOUR: Record<string, string> = {
  Critical: "text-red-400 border-red-400/30 bg-red-400/10",
  High:     "text-orange-400 border-orange-400/30 bg-orange-400/10",
  Medium:   "text-yellow-400 border-yellow-400/30 bg-yellow-400/10",
  Low:      "text-blue-400 border-blue-400/30 bg-blue-400/10",
};

function fmt(ts: string) {
  if (!ts) return "—";
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

interface PrintReportProps {
  isOpen:  boolean;
  onClose: () => void;
  loading: boolean;
  error:   string | null;
  report:  ReportData | null;
}

export default function PrintReport({ isOpen, onClose, loading, error, report }: PrintReportProps) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/80 overflow-y-auto p-4 print:p-0 print:bg-transparent">
      <div className="bg-background border border-border rounded-lg w-full max-w-5xl my-4 print:border-0 print:my-0 print:rounded-none">

        {/* Modal toolbar — hidden on print */}
        <div className="flex items-center justify-between p-4 border-b border-border print:hidden sticky top-0 bg-background z-10">
          <div className="flex items-center gap-2">
            <span className="font-mono font-semibold text-sm text-foreground">
              Security Report
            </span>
            {report && (
              <span className="text-xs font-mono text-muted-foreground">
                — {report.period}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => window.print()}
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

        {/* Report content */}
        <div className="p-6 space-y-8" id="report-content">

          {/* Loading */}
          {loading && (
            <div className="flex items-center justify-center py-24 gap-3 text-muted-foreground">
              <Loader2 className="h-5 w-5 animate-spin" />
              <span className="font-mono text-sm">
                Scanning logs — this may take up to 30 seconds…
              </span>
            </div>
          )}

          {/* Error */}
          {error && !loading && (
            <div className="flex items-center gap-2 text-destructive font-mono text-sm p-4 border border-destructive/30 rounded">
              <AlertTriangle className="h-4 w-4 flex-shrink-0" />
              {error}
            </div>
          )}

          {/* Full report */}
          {report && !loading && (
            <>
              {/* Header */}
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
                <h2 className="report-section-heading">Executive Summary</h2>
                <p className="text-sm text-muted-foreground leading-relaxed">
                  {report.executive_summary}
                </p>
              </section>

              {/* Statistics */}
              <section>
                <h2 className="report-section-heading">Key Statistics</h2>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {[
                    { label: "Total Events",      value: report.statistics.total_events.toLocaleString() },
                    { label: "Failed Logins",      value: report.statistics.failed_logins.toLocaleString() },
                    { label: "Suspicious Events",  value: report.statistics.suspicious_events.toLocaleString() },
                    { label: "Unique Sources",     value: report.statistics.unique_sources.toLocaleString() },
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
                <h2 className="report-section-heading">ML Anomaly Engine</h2>
                {report.ml_analysis.status === "active" ? (
                  <div className="p-4 rounded border border-border bg-muted/20">
                    <div className="flex items-center gap-2 mb-3">
                      <ShieldCheck className="h-4 w-4 text-accent" />
                      <span className="text-sm font-mono text-accent font-medium">Engine Active</span>
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-sm font-mono">
                      <div>
                        <div className="text-muted-foreground text-xs">Events Scored</div>
                        <div className="font-bold text-foreground">{report.ml_analysis.events_scored}</div>
                      </div>
                      <div>
                        <div className="text-muted-foreground text-xs">Zero-Day Anomalies</div>
                        <div className={`font-bold ${(report.ml_analysis.zero_day_count ?? 0) > 0 ? "text-destructive" : "text-foreground"}`}>
                          {report.ml_analysis.zero_day_count}
                        </div>
                      </div>
                      <div>
                        <div className="text-muted-foreground text-xs">High-Risk Detections</div>
                        <div className={`font-bold ${(report.ml_analysis.high_risk_count ?? 0) > 0 ? "text-orange-400" : "text-foreground"}`}>
                          {report.ml_analysis.high_risk_count}
                        </div>
                      </div>
                      <div>
                        <div className="text-muted-foreground text-xs">Anomaly Rate</div>
                        <div className="font-bold text-foreground">
                          {((report.ml_analysis.anomaly_rate ?? 0) * 100).toFixed(1)}%
                        </div>
                      </div>
                    </div>
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">ML service unavailable during report generation.</p>
                )}
              </section>

              {/* Threat Category Breakdown */}
              <section>
                <h2 className="report-section-heading">Threat Category Breakdown</h2>
                <div className="space-y-4">
                  {report.categories.map(cat => (
                    <div key={cat.key} className="border border-border rounded-lg p-4">
                      <div className="flex items-start justify-between mb-2 gap-2">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-mono font-semibold text-foreground">{cat.label}</span>
                          <span className={`text-xs px-2 py-0.5 rounded border ${LEVEL_COLOUR[cat.severity] ?? ""}`}>
                            {cat.severity}
                          </span>
                        </div>
                        <span className="font-mono font-bold text-foreground flex-shrink-0">
                          {cat.count.toLocaleString()} events
                        </span>
                      </div>

                      <p className="text-xs text-muted-foreground mb-3">
                        <span className="text-foreground font-medium">Dominant: </span>
                        {cat.dominant_threat} — {cat.description}
                      </p>

                      {/* Threat breakdown within category */}
                      {cat.threat_breakdown && cat.threat_breakdown.length > 1 && (
                        <div className="mb-3">
                          <div className="text-xs text-muted-foreground font-mono mb-1">Threat breakdown (sampled):</div>
                          <div className="flex flex-wrap gap-2">
                            {cat.threat_breakdown.map(t => (
                              <span key={t.name} className="text-xs font-mono bg-muted/40 border border-border rounded px-2 py-0.5">
                                {t.name} <span className="text-primary font-bold">×{t.count}</span>
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Sample events */}
                      {cat.sample_events.length > 0 && (
                        <div>
                          <div className="text-xs text-muted-foreground font-mono mb-1">Sample events:</div>
                          <div className="space-y-1 max-h-40 overflow-y-auto">
                            {cat.sample_events.map((e, i) => (
                              <div key={i} className="text-xs font-mono bg-muted/30 rounded px-2 py-1 flex gap-2 min-w-0">
                                <span className="text-muted-foreground flex-shrink-0">{fmt(e.timestamp)}</span>
                                <span className="text-border flex-shrink-0">|</span>
                                <span className="text-foreground/80 flex-shrink-0">{e.source}</span>
                                <span className="text-border flex-shrink-0">|</span>
                                <span className="truncate">{e.message}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </section>

              {/* CVE Correlation */}
              {report.cve_mappings.length > 0 && (
                <section>
                  <h2 className="report-section-heading">CVE Correlation</h2>
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
                          <tr key={cve.id} className="text-foreground/80 hover:bg-muted/20">
                            <td className="p-3 pr-4 text-destructive font-semibold whitespace-nowrap">{cve.id}</td>
                            <td className="p-3 pr-4 whitespace-nowrap">
                              {cve.cvss != null ? (
                                <span className={
                                  cve.cvss >= 9 ? "text-red-400 font-bold" :
                                  cve.cvss >= 7 ? "text-orange-400 font-bold" :
                                  "text-yellow-400"
                                }>
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

              {/* Prioritised Remediation Plan */}
              {report.remediation_plan.length > 0 && (
                <section>
                  <h2 className="report-section-heading">Prioritised Remediation Plan</h2>
                  <div className="space-y-4">
                    {report.remediation_plan.map((item, idx) => (
                      <div key={idx} className="border border-border rounded-lg p-4">
                        <div className="flex items-center gap-2 mb-3 flex-wrap">
                          <span className="text-xs font-mono text-muted-foreground bg-muted px-2 py-0.5 rounded">
                            Priority {idx + 1}
                          </span>
                          <span className="font-mono font-semibold text-foreground">{item.threat}</span>
                          <span className={`text-xs px-2 py-0.5 rounded border ${LEVEL_COLOUR[item.severity] ?? ""}`}>
                            {item.severity}
                          </span>
                          <span className="ml-auto text-xs text-muted-foreground font-mono">
                            {item.count.toLocaleString()} events in window
                          </span>
                        </div>
                        <ol className="space-y-1.5">
                          {item.steps.map((step, si) => (
                            <li key={si} className="flex gap-2.5 text-sm">
                              <span className="text-primary font-mono font-bold flex-shrink-0 mt-0.5">
                                {si + 1}.
                              </span>
                              <span className="text-muted-foreground">{step}</span>
                            </li>
                          ))}
                        </ol>
                      </div>
                    ))}
                  </div>
                </section>
              )}

              {/* Top Event Sources */}
              {report.top_sources.length > 0 && (
                <section>
                  <h2 className="report-section-heading">Top Event Sources</h2>
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
                <span>Report generated by OmniLog v1.0 · Catnip Games SIEM</span>
                <span>{fmt(report.generated_at)}</span>
              </div>
            </>
          )}
        </div>
      </div>

      {/* Print-only styles */}
      <style>{`
        @media print {
          body * { visibility: hidden; }
          #report-content, #report-content * { visibility: visible; }
          #report-content { position: fixed; top: 0; left: 0; width: 100%; }
          .print\\:hidden { display: none !important; }
        }
        .report-section-heading {
          font-size: 0.75rem;
          font-weight: 700;
          font-family: monospace;
          text-transform: uppercase;
          letter-spacing: 0.05em;
          color: hsl(var(--foreground));
          margin-bottom: 0.75rem;
          padding-bottom: 0.25rem;
          border-bottom: 1px solid hsl(var(--border));
        }
      `}</style>
    </div>
  );
}
