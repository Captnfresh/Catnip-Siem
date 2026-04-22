import { useEffect, useState, useCallback } from "react";
import {
  Activity, AlertTriangle, LogIn, Bug, Globe, Eye, Shield,
  Wifi, WifiOff, ChevronDown, ChevronRight, Zap, RefreshCw,
} from "lucide-react";
import {
  Sidebar, SidebarContent, SidebarGroup, SidebarGroupContent,
  SidebarGroupLabel, SidebarMenu, SidebarMenuItem, SidebarMenuButton,
  useSidebar,
} from "@/components/ui/sidebar";
import RiskGauge from "./RiskGauge";
import {
  fetchStatus, fetchDashboardCounts, fetchZeroDayAlerts,
  type StatusResponse, type DashboardCounts, type DashboardEvent,
  type ZeroDayThreat, type ZeroDayAlertsResponse,
} from "@/lib/api";

// ---------------------------------------------------------------------------
// Severity colour helpers
// ---------------------------------------------------------------------------

const SEV_COLOUR: Record<string, string> = {
  critical:  "text-red-400",
  high:      "text-orange-400",
  medium:    "text-yellow-400",
  low:       "text-blue-400",
  info:      "text-muted-foreground",
  emergency: "text-red-400",
  error:     "text-orange-400",
  warning:   "text-yellow-400",
};

function fmt(ts: string) {
  if (!ts) return "";
  try { return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); }
  catch { return ""; }
}

// ---------------------------------------------------------------------------
// Generic collapsible filter row
// ---------------------------------------------------------------------------

interface FilterRowProps {
  icon: React.ElementType;
  label: string;
  count?: number;
  isOpen: boolean;
  loading: boolean;
  onToggle: () => void;
  onRefresh?: () => void;
  children: React.ReactNode;
  accentClass?: string;
}

function FilterRow({
  icon: Icon, label, count, isOpen, loading,
  onToggle, onRefresh, children, accentClass = "hover:bg-primary/10 hover:text-primary",
}: FilterRowProps) {
  return (
    <SidebarMenuItem>
      <SidebarMenuButton onClick={onToggle} className={`${accentClass} transition-colors`}>
        <Icon className="h-4 w-4" />
        <div className="flex items-center justify-between flex-1 min-w-0">
          <span className="text-sm">{label}</span>
          <div className="flex items-center gap-1 flex-shrink-0">
            {count !== undefined && count > 0 && (
              <span className="text-xs font-mono bg-muted px-1.5 py-0.5 rounded">{count.toLocaleString()}</span>
            )}
            {isOpen
              ? <ChevronDown className="h-3 w-3 text-muted-foreground" />
              : <ChevronRight className="h-3 w-3 text-muted-foreground" />}
          </div>
        </div>
      </SidebarMenuButton>

      {isOpen && (
        <div className="mt-0.5 ml-2 border-l border-border pl-2 space-y-0.5">
          <div className="flex items-center justify-between px-1 py-0.5">
            <span className="text-xs text-muted-foreground font-mono">
              {count !== undefined ? `${count.toLocaleString()} total` : "recent events"}
            </span>
            {onRefresh && (
              <button onClick={e => { e.stopPropagation(); onRefresh(); }} className="text-muted-foreground hover:text-primary transition-colors">
                <RefreshCw className={`h-3 w-3 ${loading ? "animate-spin" : ""}`} />
              </button>
            )}
          </div>
          {children}
        </div>
      )}
    </SidebarMenuItem>
  );
}

// ---------------------------------------------------------------------------
// Standard event item (for dashboard categories)
// ---------------------------------------------------------------------------

function EventItem({ event, onClick }: { event: DashboardEvent; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="w-full text-left px-2 py-1.5 rounded hover:bg-muted/50 transition-colors"
    >
      <div className="text-xs font-mono font-medium text-foreground/90 truncate">
        {event.threat_name || event.event_type || "Event"}
      </div>
      <div className="text-xs text-muted-foreground truncate">{event.source}</div>
      <div className="flex items-center justify-between">
        <span className={`text-xs font-mono ${SEV_COLOUR[event.severity] ?? "text-muted-foreground"}`}>
          {event.severity}
        </span>
        <span className="text-xs text-muted-foreground/60 font-mono">{fmt(event.timestamp)}</span>
      </div>
    </button>
  );
}

// ---------------------------------------------------------------------------
// Zero-day threat item
// ---------------------------------------------------------------------------

function ZeroDayItem({ threat, onClick }: { threat: ZeroDayThreat; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="w-full text-left px-2 py-1.5 rounded hover:bg-muted/50 transition-colors"
    >
      <div className="flex items-start gap-1.5">
        <Zap className={`h-3 w-3 mt-0.5 flex-shrink-0 ${threat.is_zero_day ? "text-destructive" : "text-orange-400"}`} />
        <div className="min-w-0">
          <div className={`text-xs font-mono font-medium truncate ${SEV_COLOUR[threat.ml_severity] ?? "text-muted-foreground"}`}>
            {threat.attack_type}
          </div>
          <div className="text-xs text-muted-foreground truncate">{threat.source}</div>
          <div className="text-xs text-muted-foreground/60 font-mono">
            risk {(threat.combined_risk * 100).toFixed(0)}%
            {threat.is_zero_day && <span className="ml-1 text-destructive">• ZD</span>}
          </div>
        </div>
      </div>
    </button>
  );
}

// ---------------------------------------------------------------------------
// Empty / loading / error states
// ---------------------------------------------------------------------------

function Loading() {
  return (
    <div className="px-2 py-3 text-xs text-muted-foreground font-mono flex items-center gap-2">
      <Zap className="h-3 w-3 animate-pulse" /> Loading…
    </div>
  );
}

function Empty({ text }: { text: string }) {
  return <div className="px-2 py-2 text-xs text-accent font-mono">{text}</div>;
}

function Err({ text }: { text: string }) {
  return <div className="px-2 py-2 text-xs text-destructive font-mono">{text}</div>;
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

interface AppSidebarProps {
  onQuickFilter: (query: string) => void;
}

type OpenKey = "failed_logins" | "errors" | "network_activity" | "suspicious_behaviour" | "zero_day" | null;

const AppSidebar = ({ onQuickFilter }: AppSidebarProps) => {
  const { state } = useSidebar();
  const collapsed = state === "collapsed";

  const [status,   setStatus]   = useState<StatusResponse | null>(null);
  const [counts,   setCounts]   = useState<DashboardCounts | null>(null);
  const [zdData,   setZdData]   = useState<ZeroDayAlertsResponse | null>(null);
  const [openKey,  setOpenKey]  = useState<OpenKey>(null);
  const [loading,  setLoading]  = useState<Record<string, boolean>>({});
  const [errors,   setErrors]   = useState<Record<string, string | null>>({});

  // Status poll
  useEffect(() => {
    const load = () => fetchStatus().then(setStatus).catch(() => setStatus(null));
    load();
    const id = setInterval(load, 30_000);
    return () => clearInterval(id);
  }, []);

  const loadCounts = useCallback(async () => {
    setLoading(l => ({ ...l, counts: true }));
    setErrors(e => ({ ...e, counts: null }));
    try {
      setCounts(await fetchDashboardCounts());
    } catch {
      setErrors(e => ({ ...e, counts: "Could not load counts." }));
    } finally {
      setLoading(l => ({ ...l, counts: false }));
    }
  }, []);

  const loadZeroDayAlerts = useCallback(async () => {
    setLoading(l => ({ ...l, zero_day: true }));
    setErrors(e => ({ ...e, zero_day: null }));
    try {
      setZdData(await fetchZeroDayAlerts());
    } catch {
      setErrors(e => ({ ...e, zero_day: "Could not reach ML service." }));
    } finally {
      setLoading(l => ({ ...l, zero_day: false }));
    }
  }, []);

  const toggle = (key: OpenKey) => {
    const next = openKey === key ? null : key;
    setOpenKey(next);
    if (next === "zero_day" && !zdData && !loading.zero_day) {
      loadZeroDayAlerts();
    }
    if (next !== "zero_day" && next !== null && !counts && !loading.counts) {
      loadCounts();
    }
  };

  const riskScore  = status?.risk_score           ?? 42;
  const alertCount = status?.active_alerts         ?? 12;
  const graylogOk  = status?.graylog_connected     ?? false;
  const mlOk       = status?.ml_service_connected  ?? false;

  if (collapsed) {
    return (
      <Sidebar collapsible="icon" className="border-r border-border">
        <SidebarContent className="bg-sidebar">
          <SidebarGroup>
            <SidebarGroupContent>
              <div className="flex flex-col items-center gap-3 py-2">
                <div className="h-2 w-2 rounded-full bg-accent animate-pulse-glow" />
                <Activity className="h-4 w-4 text-primary" />
              </div>
            </SidebarGroupContent>
          </SidebarGroup>
          <SidebarGroup>
            <SidebarGroupContent>
              <SidebarMenu>
                {[
                  { icon: LogIn,        query: "Show failed login attempts" },
                  { icon: Bug,          query: "Show recent errors" },
                  { icon: Globe,        query: "Show network activity" },
                  { icon: Eye,          query: "Show suspicious behaviour" },
                  { icon: AlertTriangle, query: "Show zero-day anomalies" },
                ].map(({ icon: Icon, query }, i) => (
                  <SidebarMenuItem key={i}>
                    <SidebarMenuButton onClick={() => onQuickFilter(query)}>
                      <Icon className="h-4 w-4" />
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        </SidebarContent>
      </Sidebar>
    );
  }

  const catEvents = (key: keyof DashboardCounts) => counts?.[key]?.events ?? [];
  const catCount  = (key: keyof DashboardCounts) => counts?.[key]?.count;

  return (
    <Sidebar collapsible="icon" className="border-r border-border">
      <SidebarContent className="bg-sidebar">

        {/* System Status */}
        <SidebarGroup>
          <SidebarGroupLabel className="text-xs font-mono text-muted-foreground tracking-wider">
            SYSTEM STATUS
          </SidebarGroupLabel>
          <SidebarGroupContent>
            <div className="px-3 space-y-4 py-2">
              <div className="flex items-center gap-2">
                <div className="h-2 w-2 rounded-full bg-accent animate-pulse-glow" />
                <span className="text-sm text-accent font-mono">ACTIVE — MONITORING</span>
              </div>
              <RiskGauge score={riskScore} />
              <div className="flex items-center justify-between p-2 rounded-md bg-muted/50 border border-border">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-warning" />
                  <span className="text-xs text-muted-foreground">Active Alerts</span>
                </div>
                <span className="text-sm font-bold font-mono text-warning">{alertCount}</span>
              </div>
              <div className="space-y-1">
                <div className="flex items-center gap-2 text-xs font-mono">
                  {graylogOk ? <Wifi className="h-3 w-3 text-accent" /> : <WifiOff className="h-3 w-3 text-destructive" />}
                  <span className={graylogOk ? "text-accent" : "text-destructive"}>
                    Graylog {graylogOk ? "OK" : "OFFLINE"}
                  </span>
                </div>
                <div className="flex items-center gap-2 text-xs font-mono">
                  {mlOk ? <Wifi className="h-3 w-3 text-accent" /> : <WifiOff className="h-3 w-3 text-muted-foreground" />}
                  <span className={mlOk ? "text-accent" : "text-muted-foreground"}>
                    ML Engine {mlOk ? "OK" : "OFFLINE"}
                  </span>
                </div>
              </div>
            </div>
          </SidebarGroupContent>
        </SidebarGroup>

        {/* Quick Filters — all with dropdowns */}
        <SidebarGroup>
          <SidebarGroupLabel className="text-xs font-mono text-muted-foreground tracking-wider">
            QUICK FILTERS
          </SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>

              {/* Failed Logins */}
              <FilterRow
                icon={LogIn}
                label="Failed Logins"
                count={catCount("failed_logins")}
                isOpen={openKey === "failed_logins"}
                loading={!!loading.counts}
                onToggle={() => toggle("failed_logins")}
                onRefresh={loadCounts}
              >
                {loading.counts && <Loading />}
                {errors.counts && <Err text={errors.counts} />}
                {!loading.counts && catEvents("failed_logins").length === 0 && !errors.counts && (
                  <Empty text="No failed logins" />
                )}
                {catEvents("failed_logins").map((e, i) => (
                  <EventItem key={i} event={e} onClick={() =>
                    onQuickFilter(`Investigate failed login from ${e.source}: ${e.message}`)
                  } />
                ))}
              </FilterRow>

              {/* Errors */}
              <FilterRow
                icon={Bug}
                label="Errors"
                count={catCount("errors")}
                isOpen={openKey === "errors"}
                loading={!!loading.counts}
                onToggle={() => toggle("errors")}
                onRefresh={loadCounts}
              >
                {loading.counts && <Loading />}
                {errors.counts && <Err text={errors.counts} />}
                {!loading.counts && catEvents("errors").length === 0 && !errors.counts && (
                  <Empty text="No errors" />
                )}
                {catEvents("errors").map((e, i) => (
                  <EventItem key={i} event={e} onClick={() =>
                    onQuickFilter(`Investigate error on ${e.source}: ${e.message}`)
                  } />
                ))}
              </FilterRow>

              {/* Network Activity */}
              <FilterRow
                icon={Globe}
                label="Network Activity"
                count={catCount("network_activity")}
                isOpen={openKey === "network_activity"}
                loading={!!loading.counts}
                onToggle={() => toggle("network_activity")}
                onRefresh={loadCounts}
              >
                {loading.counts && <Loading />}
                {errors.counts && <Err text={errors.counts} />}
                {!loading.counts && catEvents("network_activity").length === 0 && !errors.counts && (
                  <Empty text="No network events" />
                )}
                {catEvents("network_activity").map((e, i) => (
                  <EventItem key={i} event={e} onClick={() =>
                    onQuickFilter(`Investigate network activity from ${e.source}: ${e.message}`)
                  } />
                ))}
              </FilterRow>

              {/* Suspicious Behaviour */}
              <FilterRow
                icon={Eye}
                label="Suspicious Behaviour"
                count={catCount("suspicious_behaviour")}
                isOpen={openKey === "suspicious_behaviour"}
                loading={!!loading.counts}
                onToggle={() => toggle("suspicious_behaviour")}
                onRefresh={loadCounts}
              >
                {loading.counts && <Loading />}
                {errors.counts && <Err text={errors.counts} />}
                {!loading.counts && catEvents("suspicious_behaviour").length === 0 && !errors.counts && (
                  <Empty text="No suspicious events" />
                )}
                {catEvents("suspicious_behaviour").map((e, i) => (
                  <EventItem key={i} event={e} onClick={() =>
                    onQuickFilter(`Investigate suspicious behaviour from ${e.source}: ${e.message}`)
                  } />
                ))}
              </FilterRow>

              {/* Zero-Day Alerts */}
              <FilterRow
                icon={AlertTriangle}
                label="Zero-Day Alerts"
                count={zdData?.zero_day_count}
                isOpen={openKey === "zero_day"}
                loading={!!loading.zero_day}
                onToggle={() => toggle("zero_day")}
                onRefresh={loadZeroDayAlerts}
                accentClass="hover:bg-destructive/10 hover:text-destructive"
              >
                {loading.zero_day && <Loading />}
                {errors.zero_day && <Err text={errors.zero_day} />}
                {zdData && !loading.zero_day && zdData.total_scanned > 0 && (
                  <div className="px-1 pb-0.5 text-xs text-muted-foreground font-mono">
                    {zdData.total_scanned} events scanned · {zdData.zero_day_count} anomalies
                  </div>
                )}
                {zdData && !loading.zero_day && zdData.threats.length === 0 && (
                  <Empty text="No anomalies detected" />
                )}
                {zdData && !loading.zero_day && zdData.threats.map(t => (
                  <ZeroDayItem key={t.id} threat={t} onClick={() =>
                    onQuickFilter(`Investigate ${t.attack_type} from ${t.source}: ${t.message}`)
                  } />
                ))}
                {zdData && !zdData.model_trained && !loading.zero_day && (
                  <div className="px-2 py-1 text-xs text-yellow-400/70 font-mono">
                    ⚠ Model auto-trained on current traffic
                  </div>
                )}
              </FilterRow>

            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        {/* Footer */}
        <div className="mt-auto p-4 border-t border-border">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Shield className="h-3 w-3" />
            <span className="font-mono">OmniLog v1.0</span>
          </div>
        </div>
      </SidebarContent>
    </Sidebar>
  );
};

export default AppSidebar;
