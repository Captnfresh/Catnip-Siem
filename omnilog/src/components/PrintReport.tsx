import { useState } from "react";
import { FileText, X, Printer, Loader2, AlertTriangle, ShieldCheck } from "lucide-react";
import { fetchReport, type ReportData } from "@/lib/api";

const LEVEL_COLOUR: Record<string, string> = {
  Critical: "text-red-400 border-red-400/30 bg-red-400/10",
  High:     "text-orange-400 border-orange-400/30 bg-orange-400/10",
  Medium:   "text-yellow-400 border-yellow-400/30 bg-yellow-400/10",
  Low:      "text-blue-400 border-blue-400/30 bg-blue-400/10",
};

const LEVEL_PRINT: Record<string, string> = {
  Critical: "#f87171",
  High:     "#fb923c",
  Medium:   "#facc15",
  Low:      "#60a5fa",
};

function fmt(ts: string) {
  if (!ts) return "—";
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

export default function PrintReport() {
  const [open,    setOpen]    = useState(false);
  const [loading, setLoading] = useState(false);
  const [report,  setReport]  = useState<ReportData | null>(null);
  const [error,   setError]   = useState<string | null>(null);

  const openReport = async () => {
    setOpen(true);
    if (report) return; // already loaded
    setLoading(true);
    setError(null);
    try {
      setReport(await fetchReport());
    } catch (e) {
      setError("Could not generate report — check that Graylog is connected.");
    } finally {
      setLoading(false);
    }
  };

  const refresh = async () => {
    setLoading(true);
    setError(null);
    try {
      setReport(await fetchReport());
    } catch {
      setError("Failed to refresh report.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      {/* Trigger button */}
      <button
        onClick={openReport}
        className="flex items-center gap-2 w-full px-2 py-1.5 text-xs font-mono text-muted-foreground hover:text-primary hover:bg-primary/10 rounded transition-colors"
      >
        <FileText className="h-3 w-3" />
        Generate Report
      </button>

      {/* Modal overlay */}
      {open && (
        <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/80 overflow-y-auto p-4">
          <div className="bg-background border border-border rounded-lg w-full max-w-4xl my-4 print:border-0 print:shadow-none print:my-0">

            {/* Modal header — hidden on print */}
            <div className="flex items-center justify-between p-4 border-b border-border print:hidden">
              <div className="flex items-center gap-2">
                <FileText className="h-4 w-4 text-primary" />
                <span className="font-mono font-medium text-sm">Security Report</span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={refresh}
                  disabled={loading}
                  className="text-xs font-mono text-muted-foreground hover:text-primary px-2 py-1 rounded border border-border hover:border-primary transition-colors"
                >
                  Refresh
                </button>
                <button
                  onClick={() => window.print()}
                  className="flex items-center gap-1 text-xs font-mono text-accent border border-accent/30 hover:bg-accent/10 px-2 py-1 rounded transition-colors"
                >
                  <Printer className="h-3 w-3" /> Print
                </button>
                <button onClick={() => setOpen(false)} className="text-muted-foreground hover:text-foreground">
                  <X className="h-4 w-4" />
                </button>
              </div>
            </div>

            {/* Content */}
            <div className="p-6 space-y-6" id="report-content">

              {loading && (
                <div className="flex items-center justify-center py-16 gap-3 text-muted-foreground">
                  <Loader2 className="h-5 w-5 animate-spin" />
                  <span className="font-mono text-sm">Generating report — analysing Graylog logs…</span>
                </div>
              )}

              {error && (
                <div className="flex items-center gap-2 text-destructive font-mono text-sm p-4 border border-destructive/30 rounded">
                  <AlertTriangle className="h-4 w-4" />
                  {error}
                </div>
              )}

              {report && !loading && (
                <>
                  {/* Report header */}
                  <div className="border-b border-border pb-4">
                    <h1 className="text-xl font-bold font-mono text-foreground">
                      Catnip Games — OmniLog Security Report
                    </h1>
                    <div className="flex items-center gap-4 mt-1 text-xs text-muted-foreground font-mono">
                      <span>Generated: {fmt(report.generated_at)}</span>
                      <span>Period: {report.period}</span>
                      <span
                        className={`px-2 py-0.5 rounded border font-medium ${LEVEL_COLOUR[report.overall_threat_level] ?? ""}`}
                      >
                        Threat Level: {report.overall_threat_level}
                      </span>
                    </div>
                  </div>

                  {/* Executive summary */}
                  <section>
                    <h2 className="text-sm font-bold font-mono text-foreground mb-2 uppercase tracking-wider">
                      Executive Summary
                    </h2>
                    <p className="text-sm text-muted-foreground leading-relaxed">
                      {report.executive_summary}
                    </p>
                  </section>

                  {/* Statistics */}
                  <section>
                    <h2 className="text-sm font-bold font-mono text-foreground mb-3 uppercase tracking-wider">
                      Key Statistics — {report.period}
                    </h2>
                    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                      {[
                        { label: "Total Events",      value: report.statistics.total_events.toLocaleString() },
                        { label: "Failed Logins",     value: report.statistics.failed_logins.toLocaleString() },
                        { label: "Suspicious Events", value: report.statistics.suspicious_events.toLocaleString() },
                        { label: "Unique Sources",    value: report.statistics.unique_sources.toLocaleString() },
                      ].map(s => (
                        <div key={s.label} className="p-3 rounded border border-border bg-muted/30 text-center">
                          <div className="text-lg font-bold font-mono text-foreground">{s.value}</div>
                          <div className="text-xs text-muted-foreground mt-0.5">{s.label}</div>
                        </div>
                      ))}
                    </div>
                  </section>

                  {/* ML Analysis */}
                  <section>
                    <h2 className="text-sm font-bold font-mono text-foreground mb-2 uppercase tracking-wider">
                      ML Anomaly Engine Analysis
                    </h2>
                    {report.ml_analysis.status === "active" ? (
                      <div className="flex flex-wrap gap-4 text-sm font-mono">
                        <span className="text-accent flex items-center gap-1">
                          <ShieldCheck className="h-3 w-3" /> Engine Active
                        </span>
                        <span>Events scored: <strong>{report.ml_analysis.events_scored}</strong></span>
                        <span className="text-destructive">
                          Zero-day anomalies: <strong>{report.ml_analysis.zero_day_count}</strong>
                        </span>
                        <span className="text-orange-400">
                          High-risk detections: <strong>{report.ml_analysis.high_risk_count}</strong>
                        </span>
                        <span>
                          Anomaly rate: <strong>{((report.ml_analysis.anomaly_rate ?? 0) * 100).toFixed(1)}%</strong>
                        </span>
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground">ML service unavailable during report generation.</p>
                    )}
                  </section>

                  {/* Threat categories */}
                  <section>
                    <h2 className="text-sm font-bold font-mono text-foreground mb-3 uppercase tracking-wider">
                      Threat Category Breakdown
                    </h2>
                    <div className="space-y-4">
                      {report.categories.filter(c => c.count > 0).map(cat => (
                        <div key={cat.key} className="border border-border rounded p-4">
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center gap-2">
                              <span className="font-mono font-medium text-sm text-foreground">{cat.label}</span>
                              <span className={`text-xs px-2 py-0.5 rounded border ${LEVEL_COLOUR[cat.severity] ?? ""}`}>
                                {cat.severity}
                              </span>
                            </div>
                            <span className="font-mono font-bold text-foreground">{cat.count.toLocaleString()} events</span>
                          </div>
                          <p className="text-xs text-muted-foreground mb-2">
                            <strong className="text-foreground">Dominant threat:</strong> {cat.dominant_threat} — {cat.description}
                          </p>
                          {cat.sample_events.length > 0 && (
                            <div className="mt-2">
                              <div className="text-xs text-muted-foreground font-mono mb-1">Sample events:</div>
                              <div className="space-y-1">
                                {cat.sample_events.map((e, i) => (
                                  <div key={i} className="text-xs font-mono bg-muted/30 rounded px-2 py-1 truncate">
                                    <span className="text-muted-foreground">{fmt(e.timestamp)}</span>
                                    <span className="mx-1 text-border">|</span>
                                    <span className="text-foreground/80">{e.source}</span>
                                    <span className="mx-1 text-border">|</span>
                                    <span>{e.message}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </section>

                  {/* CVE mappings */}
                  {report.cve_mappings.length > 0 && (
                    <section>
                      <h2 className="text-sm font-bold font-mono text-foreground mb-3 uppercase tracking-wider">
                        CVE Correlation
                      </h2>
                      <div className="overflow-x-auto">
                        <table className="w-full text-xs font-mono border-collapse">
                          <thead>
                            <tr className="border-b border-border text-muted-foreground text-left">
                              <th className="pb-2 pr-4">CVE ID</th>
                              <th className="pb-2 pr-4">CVSS</th>
                              <th className="pb-2 pr-4">Related Threat</th>
                              <th className="pb-2">Description</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border/50">
                            {report.cve_mappings.map(cve => (
                              <tr key={cve.id} className="text-foreground/80">
                                <td className="py-1.5 pr-4 text-destructive font-medium">{cve.id}</td>
                                <td className="py-1.5 pr-4">
                                  {cve.cvss != null
                                    ? <span className={cve.cvss >= 9 ? "text-red-400" : cve.cvss >= 7 ? "text-orange-400" : "text-yellow-400"}>
                                        {cve.cvss.toFixed(1)}
                                      </span>
                                    : "—"}
                                </td>
                                <td className="py-1.5 pr-4 text-muted-foreground">{cve.related_threat}</td>
                                <td className="py-1.5">{cve.description}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </section>
                  )}

                  {/* Remediation plan */}
                  {report.remediation_plan.length > 0 && (
                    <section>
                      <h2 className="text-sm font-bold font-mono text-foreground mb-3 uppercase tracking-wider">
                        Prioritised Remediation Plan
                      </h2>
                      <div className="space-y-4">
                        {report.remediation_plan.map((item, idx) => (
                          <div key={idx} className="border border-border rounded p-3">
                            <div className="flex items-center gap-2 mb-2">
                              <span className="text-xs font-mono text-muted-foreground">Priority {idx + 1}</span>
                              <span className="font-mono font-medium text-sm text-foreground">{item.threat}</span>
                              <span className={`text-xs px-1.5 py-0.5 rounded border ${LEVEL_COLOUR[item.severity] ?? ""}`}>
                                {item.severity}
                              </span>
                              <span className="ml-auto text-xs text-muted-foreground">{item.count.toLocaleString()} events</span>
                            </div>
                            <ol className="space-y-1">
                              {item.steps.map((step, si) => (
                                <li key={si} className="text-xs text-muted-foreground flex gap-2">
                                  <span className="text-primary font-mono font-bold flex-shrink-0">{si + 1}.</span>
                                  <span>{step}</span>
                                </li>
                              ))}
                            </ol>
                          </div>
                        ))}
                      </div>
                    </section>
                  )}

                  {/* Top sources */}
                  {report.top_sources.length > 0 && (
                    <section>
                      <h2 className="text-sm font-bold font-mono text-foreground mb-3 uppercase tracking-wider">
                        Top Event Sources
                      </h2>
                      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                        {report.top_sources.map(s => (
                          <div key={s.source} className="flex items-center justify-between text-xs font-mono p-2 rounded border border-border bg-muted/20">
                            <span className="text-foreground/80 truncate">{s.source}</span>
                            <span className="ml-2 font-bold text-foreground">{s.event_count}</span>
                          </div>
                        ))}
                      </div>
                    </section>
                  )}

                  {/* Footer */}
                  <div className="border-t border-border pt-4 text-xs text-muted-foreground font-mono">
                    Report generated by OmniLog v1.0 · Catnip Games SIEM · {fmt(report.generated_at)}
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
