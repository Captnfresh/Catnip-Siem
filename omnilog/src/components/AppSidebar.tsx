import { useEffect, useState, useCallback } from "react";
import {
  Activity, AlertTriangle, LogIn, Bug, Globe, Eye, Shield, Wifi, WifiOff,
  ChevronDown, ChevronRight, Zap, RefreshCw,
} from "lucide-react";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar";
import RiskGauge from "./RiskGauge";
import {
  fetchStatus,
  fetchZeroDayAlerts,
  type StatusResponse,
  type ZeroDayThreat,
  type ZeroDayAlertsResponse,
} from "@/lib/api";

const simpleFilters = [
  { label: "Failed Logins",        icon: LogIn,  query: "Show failed login attempts" },
  { label: "Errors",               icon: Bug,    query: "Show recent errors" },
  { label: "Network Activity",     icon: Globe,  query: "Show network activity" },
  { label: "Suspicious Behaviour", icon: Eye,    query: "Show suspicious behaviour" },
];

const SEVERITY_COLOUR: Record<string, string> = {
  critical: "text-red-400",
  high:     "text-orange-400",
  medium:   "text-yellow-400",
  low:      "text-blue-400",
  info:     "text-muted-foreground",
};

interface AppSidebarProps {
  onQuickFilter: (query: string) => void;
}

const AppSidebar = ({ onQuickFilter }: AppSidebarProps) => {
  const { state } = useSidebar();
  const collapsed = state === "collapsed";

  const [status,      setStatus]      = useState<StatusResponse | null>(null);
  const [zdData,      setZdData]      = useState<ZeroDayAlertsResponse | null>(null);
  const [zdOpen,      setZdOpen]      = useState(false);
  const [zdLoading,   setZdLoading]   = useState(false);
  const [zdError,     setZdError]     = useState<string | null>(null);

  useEffect(() => {
    const load = () => fetchStatus().then(setStatus).catch(() => setStatus(null));
    load();
    const id = setInterval(load, 30_000);
    return () => clearInterval(id);
  }, []);

  const loadZeroDayAlerts = useCallback(async () => {
    setZdLoading(true);
    setZdError(null);
    try {
      const data = await fetchZeroDayAlerts();
      setZdData(data);
    } catch (e) {
      setZdError("Could not reach ML service.");
    } finally {
      setZdLoading(false);
    }
  }, []);

  const toggleZeroDayPanel = () => {
    const next = !zdOpen;
    setZdOpen(next);
    if (next && !zdData && !zdLoading) {
      loadZeroDayAlerts();
    }
  };

  const riskScore  = status?.risk_score            ?? 42;
  const alertCount = status?.active_alerts          ?? 12;
  const graylogOk  = status?.graylog_connected      ?? false;
  const mlOk       = status?.ml_service_connected   ?? false;

  return (
    <Sidebar collapsible="icon" className="border-r border-border">
      <SidebarContent className="bg-sidebar">

        {/* System Status */}
        <SidebarGroup>
          <SidebarGroupLabel className="text-xs font-mono text-muted-foreground tracking-wider">
            {!collapsed && "SYSTEM STATUS"}
          </SidebarGroupLabel>
          <SidebarGroupContent>
            {!collapsed && (
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
                    {graylogOk
                      ? <Wifi className="h-3 w-3 text-accent" />
                      : <WifiOff className="h-3 w-3 text-destructive" />}
                    <span className={graylogOk ? "text-accent" : "text-destructive"}>
                      Graylog {graylogOk ? "OK" : "OFFLINE"}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 text-xs font-mono">
                    {mlOk
                      ? <Wifi className="h-3 w-3 text-accent" />
                      : <WifiOff className="h-3 w-3 text-muted-foreground" />}
                    <span className={mlOk ? "text-accent" : "text-muted-foreground"}>
                      ML Engine {mlOk ? "OK" : "OFFLINE"}
                    </span>
                  </div>
                </div>
              </div>
            )}
            {collapsed && (
              <div className="flex flex-col items-center gap-3 py-2">
                <div className="h-2 w-2 rounded-full bg-accent animate-pulse-glow" />
                <Activity className="h-4 w-4 text-primary" />
              </div>
            )}
          </SidebarGroupContent>
        </SidebarGroup>

        {/* Quick Filters */}
        <SidebarGroup>
          <SidebarGroupLabel className="text-xs font-mono text-muted-foreground tracking-wider">
            {!collapsed && "QUICK FILTERS"}
          </SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {simpleFilters.map((item) => (
                <SidebarMenuItem key={item.label}>
                  <SidebarMenuButton
                    onClick={() => onQuickFilter(item.query)}
                    className="hover:bg-primary/10 hover:text-primary transition-colors"
                  >
                    <item.icon className="h-4 w-4" />
                    {!collapsed && <span className="text-sm">{item.label}</span>}
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}

              {/* Zero-Day Alerts — expandable dropdown */}
              <SidebarMenuItem>
                <SidebarMenuButton
                  onClick={collapsed ? () => onQuickFilter("Show zero-day anomalies") : toggleZeroDayPanel}
                  className="hover:bg-destructive/10 hover:text-destructive transition-colors"
                >
                  <AlertTriangle className="h-4 w-4 text-destructive" />
                  {!collapsed && (
                    <div className="flex items-center justify-between flex-1">
                      <span className="text-sm font-medium">Zero-Day Alerts</span>
                      <div className="flex items-center gap-1">
                        {zdData && zdData.zero_day_count > 0 && (
                          <span className="text-xs font-mono bg-destructive/20 text-destructive px-1.5 py-0.5 rounded">
                            {zdData.zero_day_count}
                          </span>
                        )}
                        {zdOpen
                          ? <ChevronDown className="h-3 w-3 text-muted-foreground" />
                          : <ChevronRight className="h-3 w-3 text-muted-foreground" />}
                      </div>
                    </div>
                  )}
                </SidebarMenuButton>

                {/* Dropdown panel */}
                {!collapsed && zdOpen && (
                  <div className="mt-1 ml-2 border-l border-border pl-2 space-y-1">

                    {/* Header row with refresh */}
                    <div className="flex items-center justify-between px-1 py-1">
                      <span className="text-xs text-muted-foreground font-mono">
                        {zdData
                          ? `${zdData.total_scanned} events scanned`
                          : "ML anomaly scan"}
                      </span>
                      <button
                        onClick={(e) => { e.stopPropagation(); loadZeroDayAlerts(); }}
                        className="text-muted-foreground hover:text-primary transition-colors"
                        title="Refresh"
                      >
                        <RefreshCw className={`h-3 w-3 ${zdLoading ? "animate-spin" : ""}`} />
                      </button>
                    </div>

                    {zdLoading && (
                      <div className="px-2 py-3 text-xs text-muted-foreground font-mono flex items-center gap-2">
                        <Zap className="h-3 w-3 animate-pulse" />
                        Running ML scan…
                      </div>
                    )}

                    {zdError && (
                      <div className="px-2 py-2 text-xs text-destructive font-mono">
                        {zdError}
                      </div>
                    )}

                    {zdData && !zdLoading && zdData.threats.length === 0 && (
                      <div className="px-2 py-2 text-xs text-accent font-mono">
                        No anomalies detected
                      </div>
                    )}

                    {zdData && !zdLoading && zdData.threats.map((threat: ZeroDayThreat) => (
                      <button
                        key={threat.id}
                        onClick={() => onQuickFilter(
                          `Investigate ${threat.attack_type} from ${threat.source} at ${threat.timestamp}`
                        )}
                        className="w-full text-left px-2 py-1.5 rounded hover:bg-muted/50 transition-colors group"
                      >
                        <div className="flex items-start gap-1.5">
                          <Zap className={`h-3 w-3 mt-0.5 flex-shrink-0 ${
                            threat.is_zero_day ? "text-destructive" : "text-orange-400"
                          }`} />
                          <div className="min-w-0">
                            <div className={`text-xs font-mono font-medium truncate ${
                              SEVERITY_COLOUR[threat.ml_severity] ?? "text-muted-foreground"
                            }`}>
                              {threat.attack_type}
                            </div>
                            <div className="text-xs text-muted-foreground truncate">
                              {threat.source}
                            </div>
                            <div className="text-xs text-muted-foreground/60 font-mono">
                              risk {(threat.combined_risk * 100).toFixed(0)}%
                              {threat.is_zero_day && (
                                <span className="ml-1 text-destructive">• ZD</span>
                              )}
                            </div>
                          </div>
                        </div>
                      </button>
                    ))}

                    {zdData && !zdLoading && !zdData.model_trained && (
                      <div className="px-2 py-1 text-xs text-yellow-400/70 font-mono">
                        ⚠ Model auto-trained on current traffic
                      </div>
                    )}
                  </div>
                )}
              </SidebarMenuItem>
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        {/* Footer */}
        {!collapsed && (
          <div className="mt-auto p-4 border-t border-border">
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Shield className="h-3 w-3" />
              <span className="font-mono">OmniLog v1.0</span>
            </div>
          </div>
        )}
      </SidebarContent>
    </Sidebar>
  );
};

export default AppSidebar;
