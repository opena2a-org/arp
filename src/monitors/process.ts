import { execSync } from 'child_process';
import * as os from 'os';
import type { Monitor, MonitorType, ARPEvent } from '../types';
import type { EventEngine } from '../engine/event-engine';

interface ProcessInfo {
  pid: number;
  ppid: number;
  user: string;
  command: string;
  cpu: number;
  mem: number;
}

/**
 * Process monitor — tracks agent lifecycle, child processes, and resource usage.
 * Uses `ps` polling (cross-platform, no root required).
 */
export class ProcessMonitor implements Monitor {
  readonly type: MonitorType = 'process';
  private timer?: ReturnType<typeof setInterval>;
  private readonly engine: EventEngine;
  private readonly intervalMs: number;
  private knownPids = new Set<number>();
  private agentPid?: number;

  constructor(engine: EventEngine, intervalMs: number = 5000) {
    this.engine = engine;
    this.intervalMs = intervalMs;
  }

  async start(): Promise<void> {
    this.agentPid = process.ppid; // The agent that launched ARP
    this.knownPids = new Set(this.getChildPids(this.agentPid));

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
      const currentPids = this.getChildPids(this.agentPid);
      const currentSet = new Set(currentPids);

      // Detect new child processes
      for (const pid of currentPids) {
        if (!this.knownPids.has(pid)) {
          const info = this.getProcessInfo(pid);
          if (info) {
            this.engine.emit({
              source: 'process',
              category: 'normal',
              severity: 'info',
              description: `New child process: PID ${pid} — ${info.command.slice(0, 100)}`,
              data: { pid, command: info.command, user: info.user, cpu: info.cpu, mem: info.mem },
            });
          }
        }
      }

      // Detect terminated processes
      for (const pid of this.knownPids) {
        if (!currentSet.has(pid)) {
          this.engine.emit({
            source: 'process',
            category: 'normal',
            severity: 'info',
            description: `Child process terminated: PID ${pid}`,
            data: { pid, action: 'terminated' },
          });
        }
      }

      // Check for suspicious processes (high CPU, unexpected users)
      for (const pid of currentPids) {
        const info = this.getProcessInfo(pid);
        if (!info) continue;

        // High CPU for extended period
        if (info.cpu > 90) {
          this.engine.emit({
            source: 'process',
            category: 'anomaly',
            severity: 'medium',
            description: `High CPU usage: PID ${pid} at ${info.cpu}% — ${info.command.slice(0, 60)}`,
            data: { pid, cpu: info.cpu, command: info.command },
          });
        }

        // Running as different user
        if (info.user === 'root' && os.userInfo().username !== 'root') {
          this.engine.emit({
            source: 'process',
            category: 'violation',
            severity: 'high',
            description: `Child process running as root: PID ${pid} — ${info.command.slice(0, 60)}`,
            data: { pid, user: info.user, command: info.command },
          });
        }
      }

      this.knownPids = currentSet;
    } catch {
      // ps command failed — skip this cycle
    }
  }

  private getChildPids(parentPid?: number): number[] {
    if (!parentPid) return [];
    try {
      const platform = os.platform();
      let cmd: string;
      if (platform === 'darwin') {
        cmd = `ps -o pid= -g ${parentPid}`;
      } else {
        cmd = `ps -o pid= --ppid ${parentPid}`;
      }
      const output = execSync(cmd, { encoding: 'utf-8', timeout: 5000 });
      return output.trim().split('\n').map((s) => parseInt(s.trim())).filter((n) => !isNaN(n) && n !== parentPid);
    } catch {
      return [];
    }
  }

  private getProcessInfo(pid: number): ProcessInfo | null {
    try {
      const output = execSync(
        `ps -o pid=,ppid=,user=,%cpu=,%mem=,command= -p ${pid}`,
        { encoding: 'utf-8', timeout: 5000 },
      );
      const line = output.trim();
      if (!line) return null;

      const parts = line.trim().split(/\s+/);
      if (parts.length < 6) return null;

      return {
        pid: parseInt(parts[0]),
        ppid: parseInt(parts[1]),
        user: parts[2],
        cpu: parseFloat(parts[3]),
        mem: parseFloat(parts[4]),
        command: parts.slice(5).join(' '),
      };
    } catch {
      return null;
    }
  }
}
