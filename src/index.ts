export const VERSION = '0.1.0';

// Re-export types
export type {
  ARPConfig,
  ARPEvent,
  MonitorType,
  EventCategory,
  EventSeverity,
  LLMAdapter,
  LLMAdapterType,
  LLMAssessment,
  LLMResponse,
  IntelligenceConfig,
  BudgetState,
  AlertRule,
  AlertCondition,
  MonitorConfig,
  EnforcementAction,
  EnforcementResult,
  Monitor,
} from './types';

// Re-export components
export { EventEngine } from './engine/event-engine';
export { IntelligenceCoordinator } from './intelligence/coordinator';
export { BudgetController } from './intelligence/budget';
export { AnomalyDetector } from './intelligence/anomaly';
export { AnthropicAdapter, OpenAIAdapter, OllamaAdapter, createAdapter, autoDetectAdapter } from './intelligence/adapters';
export { ProcessMonitor } from './monitors/process';
export { NetworkMonitor } from './monitors/network';
export { FilesystemMonitor } from './monitors/filesystem';
export { EnforcementEngine } from './enforcement/kill-switch';
export { LocalLogger } from './reporting/local-log';
export { loadConfig, defaultConfig } from './config/loader';

import * as path from 'path';
import type { ARPConfig, ARPEvent, Monitor } from './types';
import { EventEngine } from './engine/event-engine';
import { IntelligenceCoordinator } from './intelligence/coordinator';
import { EnforcementEngine } from './enforcement/kill-switch';
import { LocalLogger } from './reporting/local-log';
import { ProcessMonitor } from './monitors/process';
import { NetworkMonitor } from './monitors/network';
import { FilesystemMonitor } from './monitors/filesystem';
import { loadConfig } from './config/loader';

/**
 * Agent Runtime Protection — the main entry point.
 *
 * Provides 3-layer intelligent monitoring for AI agents:
 * - L0: Rule-based event classification (free, every event)
 * - L1: Statistical anomaly detection (free, flagged events)
 * - L2: LLM-assisted assessment (micro-prompts, budget-controlled)
 *
 * Usage:
 *   const arp = new AgentRuntimeProtection({ agentName: 'my-agent' });
 *   await arp.start();
 *   // ... agent runs ...
 *   await arp.stop();
 */
export class AgentRuntimeProtection {
  private readonly config: ARPConfig;
  private readonly engine: EventEngine;
  private readonly intelligence: IntelligenceCoordinator;
  private readonly enforcement: EnforcementEngine;
  private readonly logger: LocalLogger;
  private readonly monitors: Monitor[] = [];
  private running = false;

  constructor(configOrPath?: ARPConfig | string) {
    if (typeof configOrPath === 'string') {
      this.config = loadConfig(configOrPath);
    } else {
      this.config = configOrPath ?? loadConfig();
    }

    const dataDir = this.config.dataDir ?? path.join(process.cwd(), '.opena2a', 'arp');

    this.engine = new EventEngine(this.config);
    this.intelligence = new IntelligenceCoordinator(this.config, dataDir);
    this.enforcement = new EnforcementEngine();
    this.logger = new LocalLogger(dataDir);

    // Wire up: events → intelligence → logger
    this.engine.onEvent(async (event) => {
      await this.intelligence.analyze(event);
      this.logger.logEvent(event);
    });

    // Wire up: enforcement → logger
    this.engine.onEnforcement(async (result) => {
      const enforced = await this.enforcement.execute(result.action, result.event);
      this.logger.logEnforcement(enforced);
    });

    // Create monitors based on config
    const mc = this.config.monitors;
    if (mc?.process?.enabled !== false) {
      this.monitors.push(new ProcessMonitor(this.engine, mc?.process?.intervalMs));
    }
    if (mc?.network?.enabled !== false) {
      this.monitors.push(new NetworkMonitor(this.engine, mc?.network?.intervalMs, mc?.network?.allowedHosts));
    }
    if (mc?.filesystem?.enabled !== false) {
      this.monitors.push(new FilesystemMonitor(this.engine, mc?.filesystem?.watchPaths, mc?.filesystem?.allowedPaths));
    }
  }

  /** Start all monitors */
  async start(): Promise<void> {
    if (this.running) return;

    for (const monitor of this.monitors) {
      await monitor.start();
    }

    this.running = true;
  }

  /** Stop all monitors and flush logs */
  async stop(): Promise<void> {
    if (!this.running) return;

    for (const monitor of this.monitors) {
      await monitor.stop();
    }

    await this.intelligence.stop();
    this.running = false;
  }

  /** Check if ARP is running */
  isRunning(): boolean {
    return this.running;
  }

  /** Get current status */
  getStatus(): {
    running: boolean;
    monitors: Array<{ type: string; running: boolean }>;
    budget: ReturnType<IntelligenceCoordinator['getBudgetStatus']>;
    pausedPids: number[];
  } {
    return {
      running: this.running,
      monitors: this.monitors.map((m) => ({ type: m.type, running: m.isRunning() })),
      budget: this.intelligence.getBudgetStatus(),
      pausedPids: this.enforcement.getPausedPids(),
    };
  }

  /** Get recent events */
  getEvents(limit?: number): ARPEvent[] {
    return this.logger.readEvents(limit);
  }

  /** Resume a paused process */
  resume(pid: number): boolean {
    return this.enforcement.resume(pid);
  }

  /** Get the event engine (for custom integrations) */
  getEngine(): EventEngine {
    return this.engine;
  }
}
