export interface LogEntry {
  timestamp: string;
  source: string;
  level: "INFO" | "WARNING" | "ERROR" | "CRITICAL";
  message: string;
}

export interface CveEntry {
  id: string;
  description: string;
  cvss: number | null;
}

export interface MlPrediction {
  severity: string;
  confidence: number;
  zeroDayScore: number;
  isZeroDay: boolean;
  combinedRisk: number;
}

export interface ThreatAnalysis {
  summary: string;
  threatLevel: "Low" | "Medium" | "High" | "Critical";
  affectedSystems: string[];
  recommendedActions: string[];
  logEntries: LogEntry[];
  cves?: CveEntry[];
  mlPrediction?: MlPrediction;
  conversationalReply?: string;
  sessionId?: string;
}

const sampleLogs: LogEntry[] = [
  { timestamp: "2026-04-03T14:23:01Z", source: "auth-server-01", level: "WARNING", message: "Failed login attempt for user admin from IP 192.168.1.105" },
  { timestamp: "2026-04-03T14:23:15Z", source: "auth-server-01", level: "WARNING", message: "Failed login attempt for user admin from IP 192.168.1.105" },
  { timestamp: "2026-04-03T14:23:28Z", source: "auth-server-01", level: "ERROR", message: "Multiple failed login attempts detected - account lockout triggered for admin" },
  { timestamp: "2026-04-03T14:24:02Z", source: "firewall-gw", level: "WARNING", message: "Port scan detected from external IP 45.33.32.156 targeting ports 22,80,443,8080" },
  { timestamp: "2026-04-03T14:24:18Z", source: "ids-sensor-02", level: "CRITICAL", message: "Possible brute force attack detected from 45.33.32.156" },
  { timestamp: "2026-04-03T14:25:00Z", source: "web-server-03", level: "ERROR", message: "SQL injection attempt blocked: SELECT * FROM users WHERE id=1 OR 1=1" },
  { timestamp: "2026-04-03T14:25:30Z", source: "network-mon", level: "INFO", message: "Unusual outbound traffic spike from 10.0.0.42 to external endpoint" },
  { timestamp: "2026-04-03T14:26:00Z", source: "endpoint-sec", level: "WARNING", message: "Unauthorized process execution detected on workstation WS-0142" },
  { timestamp: "2026-04-03T14:26:45Z", source: "dns-server", level: "INFO", message: "DNS query for known malicious domain blocked: evil-payload.example.com" },
  { timestamp: "2026-04-03T14:27:10Z", source: "vpn-gateway", level: "WARNING", message: "VPN connection from unusual geolocation: Russia (user: jsmith)" },
];

export function getRelevantLogs(query: string): LogEntry[] {
  const q = query.toLowerCase();
  if (q.includes("failed login") || q.includes("login")) {
    return sampleLogs.filter(l => l.message.toLowerCase().includes("login"));
  }
  if (q.includes("error")) {
    return sampleLogs.filter(l => l.level === "ERROR" || l.level === "CRITICAL");
  }
  if (q.includes("network")) {
    return sampleLogs.filter(l => l.source.includes("network") || l.source.includes("firewall") || l.message.toLowerCase().includes("traffic"));
  }
  if (q.includes("suspicious") || q.includes("threat") || q.includes("attack")) {
    return sampleLogs.filter(l => l.level === "WARNING" || l.level === "CRITICAL");
  }
  return sampleLogs.slice(0, 6);
}

export function generateMockAnalysis(query: string): ThreatAnalysis {
  const logs = getRelevantLogs(query);
  const q = query.toLowerCase();

  if (q.includes("failed login") || q.includes("login")) {
    return {
      summary: "Multiple failed login attempts detected targeting the admin account from internal IP 192.168.1.105. The account has been automatically locked after 3 consecutive failures. Additionally, a brute-force attack signature was detected from an external IP address.",
      threatLevel: "High",
      affectedSystems: ["auth-server-01", "Active Directory"],
      recommendedActions: [
        "Investigate the source IP 192.168.1.105 — verify if it's a compromised internal device",
        "Block external IP 45.33.32.156 at the firewall level",
        "Enable MFA for all admin accounts immediately",
        "Review VPN access logs for the locked account",
      ],
      logEntries: logs,
    };
  }

  if (q.includes("error")) {
    return {
      summary: "Critical errors detected across multiple systems. A SQL injection attempt was blocked on web-server-03, and an account lockout was triggered on the authentication server due to repeated failures.",
      threatLevel: "Medium",
      affectedSystems: ["web-server-03", "auth-server-01"],
      recommendedActions: [
        "Verify WAF rules are up to date on web-server-03",
        "Audit all SQL query parameterization in the application layer",
        "Review auth-server logs for patterns of automated attacks",
      ],
      logEntries: logs,
    };
  }

  if (q.includes("network")) {
    return {
      summary: "Unusual network activity detected: an outbound traffic spike from internal host 10.0.0.42 and a port scan from external IP 45.33.32.156. The port scan targeted common service ports (22, 80, 443, 8080).",
      threatLevel: "Medium",
      affectedSystems: ["network-mon", "firewall-gw", "10.0.0.42"],
      recommendedActions: [
        "Isolate host 10.0.0.42 and investigate for potential data exfiltration",
        "Add 45.33.32.156 to the blocklist",
        "Review firewall rules for unnecessary open ports",
      ],
      logEntries: logs,
    };
  }

  return {
    summary: "In the last 10 minutes, OmniLog detected multiple security events: brute-force login attempts, a SQL injection attempt, suspicious network activity, and a VPN login from an unusual geolocation. The overall threat posture is elevated.",
    threatLevel: "High",
    affectedSystems: ["auth-server-01", "web-server-03", "firewall-gw", "vpn-gateway", "10.0.0.42"],
    recommendedActions: [
      "Escalate to the SOC team for immediate investigation",
      "Block identified malicious IPs at the perimeter firewall",
      "Force password rotation for all admin accounts",
      "Enable enhanced logging on all critical systems",
      "Run a full endpoint scan on workstation WS-0142",
    ],
    logEntries: logs,
  };
}
