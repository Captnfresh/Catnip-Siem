import { useState, useRef, useEffect } from "react";
import { Shield, Wifi, WifiOff, User, FileText, ChevronDown, Clock } from "lucide-react";
import { SidebarTrigger } from "@/components/ui/sidebar";
import PrintReport from "./PrintReport";
import { fetchReport, type ReportData } from "@/lib/api";

// ---------------------------------------------------------------------------
// Time-range helpers
// ---------------------------------------------------------------------------

type QuickRange = "1h" | "6h" | "24h" | "7d" | "custom";

function toLocalInput(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}` +
    `T${pad(date.getHours())}:${pad(date.getMinutes())}`
  );
}

function rangePreset(range: Exclude<QuickRange, "custom">): { from: string; to: string } {
  const now = new Date();
  const hours: Record<typeof range, number> = { "1h": 1, "6h": 6, "24h": 24, "7d": 168 };
  const from = new Date(now.getTime() - hours[range] * 3_600_000);
  return { from: toLocalInput(from), to: toLocalInput(now) };
}

const QUICK_RANGES: { label: string; value: Exclude<QuickRange, "custom"> }[] = [
  { label: "Last 1 hour",   value: "1h"  },
  { label: "Last 6 hours",  value: "6h"  },
  { label: "Last 24 hours", value: "24h" },
  { label: "Last 7 days",   value: "7d"  },
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface TopBarProps {
  isConnected: boolean;
}

const TopBar = ({ isConnected }: TopBarProps) => {
  const [menuOpen,   setMenuOpen]   = useState(false);
  const [quickRange, setQuickRange] = useState<QuickRange>("1h");
  const [fromInput,  setFromInput]  = useState(() => rangePreset("1h").from);
  const [toInput,    setToInput]    = useState(() => rangePreset("1h").to);
  const [reportOpen, setReportOpen] = useState(false);
  const [loading,    setLoading]    = useState(false);
  const [error,      setError]      = useState<string | null>(null);
  const [report,     setReport]     = useState<ReportData | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const applyQuickRange = (value: Exclude<QuickRange, "custom">) => {
    const { from, to } = rangePreset(value);
    setQuickRange(value);
    setFromInput(from);
    setToInput(to);
  };

  const generateReport = async () => {
    setMenuOpen(false);
    setReportOpen(true);
    setReport(null);
    setLoading(true);
    setError(null);
    try {
      const fromTs = fromInput ? new Date(fromInput).toISOString() : undefined;
      const toTs   = toInput   ? new Date(toInput).toISOString()   : undefined;
      setReport(await fetchReport({ fromTs, toTs }));
    } catch {
      setError("Could not generate report — check that Graylog and the ML service are connected.");
    } finally {
      setLoading(false);
    }
  };

  const rangeLabel =
    quickRange === "custom"
      ? `${fromInput.replace("T", " ")} → ${toInput.replace("T", " ")}`
      : QUICK_RANGES.find(r => r.value === quickRange)?.label ?? "";

  return (
    <>
      <header className="h-14 flex items-center justify-between px-4 border-b border-border bg-card/50 backdrop-blur-sm z-20 relative">

        {/* Left — sidebar toggle + branding */}
        <div className="flex items-center gap-3">
          <SidebarTrigger className="text-muted-foreground hover:text-foreground" />
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-primary" />
            <h1 className="text-lg font-semibold font-mono tracking-tight text-foreground">
              Omni<span className="text-primary text-glow-primary">Log</span>
            </h1>
          </div>
        </div>

        {/* Right — connection + Print Report + avatar */}
        <div className="flex items-center gap-3">

          {/* Connection pill */}
          <div className="flex items-center gap-2">
            {isConnected ? (
              <>
                <Wifi className="h-4 w-4 text-accent" />
                <span className="text-accent font-mono text-xs hidden sm:inline">CONNECTED</span>
              </>
            ) : (
              <>
                <WifiOff className="h-4 w-4 text-destructive" />
                <span className="text-destructive font-mono text-xs hidden sm:inline">DISCONNECTED</span>
              </>
            )}
          </div>

          {/* Print Report dropdown */}
          <div ref={menuRef} className="relative">
            <button
              onClick={() => setMenuOpen(o => !o)}
              className="flex items-center gap-1.5 h-8 px-3 rounded-md border border-border bg-muted/50 hover:bg-muted hover:border-primary/40 text-sm font-mono text-foreground transition-colors"
            >
              <FileText className="h-3.5 w-3.5 text-primary" />
              <span className="hidden sm:inline">Print Report</span>
              <ChevronDown className={`h-3 w-3 text-muted-foreground transition-transform duration-150 ${menuOpen ? "rotate-180" : ""}`} />
            </button>

            {menuOpen && (
              <div className="absolute right-0 top-[calc(100%+6px)] w-80 bg-card border border-border rounded-lg shadow-2xl z-50 p-4 space-y-4">

                {/* Panel header */}
                <div className="flex items-center justify-between pb-2 border-b border-border">
                  <div className="flex items-center gap-2">
                    <Clock className="h-3.5 w-3.5 text-primary" />
                    <span className="text-xs font-mono font-semibold text-foreground uppercase tracking-wider">
                      Select Time Range
                    </span>
                  </div>
                  <span className="text-xs text-muted-foreground font-mono">≤ 10 000 logs</span>
                </div>

                {/* Quick-range pills */}
                <div className="grid grid-cols-2 gap-1.5">
                  {QUICK_RANGES.map(r => (
                    <button
                      key={r.value}
                      onClick={() => applyQuickRange(r.value)}
                      className={`text-xs font-mono px-2 py-1.5 rounded border transition-colors ${
                        quickRange === r.value
                          ? "bg-primary/20 border-primary/60 text-primary"
                          : "border-border text-muted-foreground hover:border-primary/30 hover:text-foreground"
                      }`}
                    >
                      {r.label}
                    </button>
                  ))}
                </div>

                {/* Custom date/time inputs */}
                <div className="space-y-2">
                  <div className="text-xs font-mono text-muted-foreground uppercase tracking-wider">
                    Custom timestamp
                  </div>
                  <div className="space-y-2">
                    <div>
                      <label className="text-xs text-muted-foreground font-mono block mb-1">From</label>
                      <input
                        type="datetime-local"
                        value={fromInput}
                        onChange={e => { setFromInput(e.target.value); setQuickRange("custom"); }}
                        className="w-full text-xs font-mono px-2 py-1.5 rounded border border-border bg-background text-foreground focus:outline-none focus:border-primary transition-colors"
                      />
                    </div>
                    <div>
                      <label className="text-xs text-muted-foreground font-mono block mb-1">To</label>
                      <input
                        type="datetime-local"
                        value={toInput}
                        onChange={e => { setToInput(e.target.value); setQuickRange("custom"); }}
                        className="w-full text-xs font-mono px-2 py-1.5 rounded border border-border bg-background text-foreground focus:outline-none focus:border-primary transition-colors"
                      />
                    </div>
                  </div>
                </div>

                {/* Selected range summary */}
                <div className="text-xs font-mono text-muted-foreground bg-muted/40 rounded px-2 py-1.5 border border-border/50">
                  <span className="text-foreground/70">Range: </span>{rangeLabel}
                </div>

                {/* Generate button */}
                <button
                  onClick={generateReport}
                  disabled={!fromInput || !toInput}
                  className="w-full flex items-center justify-center gap-2 py-2 rounded-md bg-primary text-primary-foreground font-mono text-sm font-medium hover:bg-primary/90 disabled:opacity-40 transition-colors"
                >
                  <FileText className="h-3.5 w-3.5" />
                  Generate &amp; Print Report
                </button>
              </div>
            )}
          </div>

          {/* User avatar */}
          <div className="h-8 w-8 rounded-full bg-secondary flex items-center justify-center border border-border flex-shrink-0">
            <User className="h-4 w-4 text-muted-foreground" />
          </div>
        </div>
      </header>

      {/* Report modal — rendered at this level so it sits above everything */}
      <PrintReport
        isOpen={reportOpen}
        onClose={() => setReportOpen(false)}
        loading={loading}
        error={error}
        report={report}
      />
    </>
  );
};

export default TopBar;
