import { execSync } from 'child_process';
import * as os from 'os';
import type { Monitor, MonitorType } from '../types';
import type { EventEngine } from '../engine/event-engine';

interface Connection {
  protocol: string;
  localAddr: string;
  localPort: number;
  remoteAddr: string;
  remotePort: number;
  state: string;
  pid?: number;
}

/** Known exfiltration/suspicious destinations */
const SUSPICIOUS_HOSTS = [
  'webhook.site', 'requestbin', 'ngrok.io', 'pipedream.net',
  'hookbin.com', 'burpcollaborator', 'interact.sh', 'oastify.com',
  'pastebin.com', 'transfer.sh',
];

/**
 * Network monitor — tracks outbound connections using lsof/ss.
 * Detects connections to suspicious hosts, new outbound destinations,
 * and unexpected port usage.
 */
export class NetworkMonitor implements Monitor {
  readonly type: MonitorType = 'network';
  private timer?: ReturnType<typeof setInterval>;
  private readonly engine: EventEngine;
  private readonly intervalMs: number;
  private readonly allowedHosts: Set<string>;
  private knownDestinations = new Set<string>();

  constructor(engine: EventEngine, intervalMs: number = 10000, allowedHosts?: string[]) {
    this.engine = engine;
    this.intervalMs = intervalMs;
    this.allowedHosts = new Set(allowedHosts ?? []);
  }

  async start(): Promise<void> {
    // Initial snapshot
    const connections = this.getConnections();
    for (const conn of connections) {
      this.knownDestinations.add(`${conn.remoteAddr}:${conn.remotePort}`);
    }

    this.timer = setInterval(() => this.poll(), this.intervalMs);
    if (this.timer.unref) this.timer.unref();
  }

  async stop(): Promise<void> {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }

  isRunning(): boolean {
    return this.timer !== undefined;
  }

  private poll(): void {
    try {
      const connections = this.getConnections();

      for (const conn of connections) {
        const dest = `${conn.remoteAddr}:${conn.remotePort}`;

        // Check for suspicious hosts
        const isSuspicious = SUSPICIOUS_HOSTS.some((h) =>
          conn.remoteAddr.includes(h)
        );

        if (isSuspicious) {
          this.engine.emit({
            source: 'network',
            category: 'threat',
            severity: 'critical',
            description: `Connection to suspicious host: ${dest}`,
            data: {
              remoteAddr: conn.remoteAddr,
              remotePort: conn.remotePort,
              protocol: conn.protocol,
              pid: conn.pid,
            },
          });
          continue;
        }

        // Check for new outbound destinations
        if (!this.knownDestinations.has(dest)) {
          const isAllowed = this.allowedHosts.size === 0 ||
            this.allowedHosts.has(conn.remoteAddr) ||
            Array.from(this.allowedHosts).some((h) =>
              conn.remoteAddr === h || conn.remoteAddr.endsWith('.' + h)
            );

          this.engine.emit({
            source: 'network',
            category: isAllowed ? 'normal' : 'anomaly',
            severity: isAllowed ? 'info' : 'medium',
            description: `New outbound connection: ${dest}`,
            data: {
              remoteAddr: conn.remoteAddr,
              remotePort: conn.remotePort,
              protocol: conn.protocol,
              pid: conn.pid,
              allowed: isAllowed,
            },
          });

          this.knownDestinations.add(dest);
        }
      }
    } catch {
      // lsof/ss failed — skip
    }
  }

  private getConnections(): Connection[] {
    const platform = os.platform();
    try {
      if (platform === 'darwin') {
        return this.parseLsof();
      } else {
        return this.parseSs();
      }
    } catch {
      return [];
    }
  }

  private parseLsof(): Connection[] {
    const connections: Connection[] = [];
    try {
      const output = execSync(
        'lsof -i -n -P 2>/dev/null | grep ESTABLISHED',
        { encoding: 'utf-8', timeout: 5000 },
      );

      for (const line of output.trim().split('\n')) {
        if (!line) continue;
        const parts = line.split(/\s+/);
        if (parts.length < 9) continue;

        const nameField = parts[8] ?? '';
        const match = nameField.match(/(\S+):(\d+)->(\S+):(\d+)/);
        if (!match) continue;

        connections.push({
          protocol: parts[7]?.includes('TCP') ? 'tcp' : 'udp',
          localAddr: match[1],
          localPort: parseInt(match[2]),
          remoteAddr: match[3],
          remotePort: parseInt(match[4]),
          state: 'ESTABLISHED',
          pid: parseInt(parts[1]) || undefined,
        });
      }
    } catch {
      // lsof not available or no connections
    }
    return connections;
  }

  private parseSs(): Connection[] {
    const connections: Connection[] = [];
    try {
      const output = execSync(
        'ss -tpn state established 2>/dev/null',
        { encoding: 'utf-8', timeout: 5000 },
      );

      for (const line of output.trim().split('\n').slice(1)) {
        if (!line) continue;
        const parts = line.split(/\s+/);
        if (parts.length < 5) continue;

        const local = parts[3]?.split(':') ?? [];
        const remote = parts[4]?.split(':') ?? [];

        connections.push({
          protocol: 'tcp',
          localAddr: local.slice(0, -1).join(':'),
          localPort: parseInt(local[local.length - 1] ?? '0'),
          remoteAddr: remote.slice(0, -1).join(':'),
          remotePort: parseInt(remote[remote.length - 1] ?? '0'),
          state: 'ESTABLISHED',
        });
      }
    } catch {
      // ss not available
    }
    return connections;
  }
}
