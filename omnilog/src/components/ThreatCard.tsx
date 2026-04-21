import { motion } from "framer-motion";
import { AlertTriangle, Shield, ShieldAlert, ShieldCheck, Server, ArrowRight, Brain, ExternalLink } from "lucide-react";
import type { ThreatAnalysis } from "@/lib/mock-logs";

interface ThreatCardProps {
  analysis: ThreatAnalysis;
}

const levelConfig = {
  Low: { icon: ShieldCheck, colorClass: "text-accent", bgClass: "bg-accent/10", borderClass: "border-accent/30" },
  Medium: { icon: Shield, colorClass: "text-warning", bgClass: "bg-warning/10", borderClass: "border-warning/30" },
  High: { icon: AlertTriangle, colorClass: "text-neon-orange", bgClass: "bg-warning/10", borderClass: "border-warning/30" },
  Critical: { icon: ShieldAlert, colorClass: "text-destructive", bgClass: "bg-destructive/10", borderClass: "border-destructive/30" },
};

const ThreatCard = ({ analysis }: ThreatCardProps) => {
  const config = levelConfig[analysis.threatLevel];
  const Icon = config.icon;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={`rounded-lg border ${config.borderClass} ${config.bgClass} p-4 space-y-3`}
    >
      {/* Threat Level Badge + ML Prediction */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <Icon className={`h-4 w-4 ${config.colorClass}`} />
          <span className={`text-xs font-mono font-bold uppercase tracking-wider ${config.colorClass}`}>
            {analysis.threatLevel} Threat
          </span>
          {analysis.mlPrediction?.isZeroDay && (
            <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-destructive/20 border border-destructive/40 text-destructive animate-pulse">
              ZERO-DAY
            </span>
          )}
        </div>
        {analysis.mlPrediction && (
          <div className="flex items-center gap-1.5 text-xs font-mono text-muted-foreground">
            <Brain className="h-3 w-3 text-primary" />
            <span className="text-primary">{analysis.mlPrediction.severity.toUpperCase()}</span>
            <span>·</span>
            <span>conf {(analysis.mlPrediction.confidence * 100).toFixed(0)}%</span>
            <span>·</span>
            <span>risk {(analysis.mlPrediction.combinedRisk * 100).toFixed(0)}</span>
          </div>
        )}
      </div>

      {/* Summary */}
      <p className="text-sm text-foreground/90 leading-relaxed">{analysis.summary}</p>

      {/* Affected Systems */}
      {analysis.affectedSystems.length > 0 && (
        <div className="space-y-1.5">
          <span className="text-xs font-mono text-muted-foreground">AFFECTED SYSTEMS</span>
          <div className="flex flex-wrap gap-1.5">
            {analysis.affectedSystems.map((sys) => (
              <span key={sys} className="inline-flex items-center gap-1 text-xs font-mono px-2 py-1 rounded bg-muted border border-border">
                <Server className="h-3 w-3 text-muted-foreground" />
                {sys}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Recommended Actions */}
      <div className="space-y-1.5">
        <span className="text-xs font-mono text-muted-foreground">RECOMMENDED ACTIONS</span>
        <ul className="space-y-1">
          {analysis.recommendedActions.map((action, i) => (
            <li key={i} className="flex items-start gap-2 text-sm text-foreground/80">
              <ArrowRight className="h-3 w-3 mt-1 text-primary shrink-0" />
              {action}
            </li>
          ))}
        </ul>
      </div>

      {/* CVE Mappings */}
      {analysis.cves && analysis.cves.length > 0 && (
        <div className="space-y-1.5">
          <span className="text-xs font-mono text-muted-foreground">RELATED CVEs</span>
          <div className="flex flex-wrap gap-1.5">
            {analysis.cves.map((cve) => (
              <a
                key={cve.id}
                href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                target="_blank"
                rel="noopener noreferrer"
                title={cve.description}
                className="inline-flex items-center gap-1 text-xs font-mono px-2 py-1 rounded bg-destructive/10 border border-destructive/30 text-destructive hover:bg-destructive/20 transition-colors"
              >
                {cve.id}
                {cve.cvss !== null && (
                  <span className="ml-1 text-[10px] opacity-70">CVSS {cve.cvss}</span>
                )}
                <ExternalLink className="h-2.5 w-2.5 opacity-60" />
              </a>
            ))}
          </div>
        </div>
      )}

      {/* Log Entries */}
      {analysis.logEntries.length > 0 && (
        <details className="group">
          <summary className="text-xs font-mono text-muted-foreground cursor-pointer hover:text-foreground transition-colors">
            VIEW RAW LOGS ({analysis.logEntries.length})
          </summary>
          <div className="mt-2 space-y-1 max-h-40 overflow-y-auto">
            {analysis.logEntries.map((log, i) => {
              const levelColor =
                log.level === "CRITICAL" ? "text-destructive" :
                log.level === "ERROR" ? "text-neon-orange" :
                log.level === "WARNING" ? "text-warning" : "text-muted-foreground";
              return (
                <div key={i} className="text-xs font-mono p-1.5 rounded bg-background/50 border border-border/50">
                  <span className="text-muted-foreground">{new Date(log.timestamp).toLocaleTimeString()}</span>
                  {" "}
                  <span className={levelColor}>[{log.level}]</span>
                  {" "}
                  <span className="text-primary/70">{log.source}</span>
                  {" — "}
                  <span className="text-foreground/70">{log.message}</span>
                </div>
              );
            })}
          </div>
        </details>
      )}
    </motion.div>
  );
};

export default ThreatCard;
