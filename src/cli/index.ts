#!/usr/bin/env node

import { AgentRuntimeProtection, VERSION, loadConfig } from '../index';

const args = process.argv.slice(2);
const command = args[0];

async function main(): Promise<void> {
  switch (command) {
    case 'start':
      await startGuard();
      break;
    case 'stop':
      console.log('Stop not implemented in foreground mode. Use Ctrl+C.');
      break;
    case 'status':
      await showStatus();
      break;
    case 'tail':
      await tailEvents();
      break;
    case 'budget':
      await showBudget();
      break;
    case '--version':
    case '-v':
      console.log(`arp-guard v${VERSION}`);
      break;
    case '--help':
    case '-h':
    case undefined:
      showHelp();
      break;
    default:
      console.error(`Unknown command: ${command}`);
      showHelp();
      process.exit(1);
  }
}

async function startGuard(): Promise<void> {
  const configPath = args.find((a) => a.startsWith('--config='))?.split('=')[1]
    ?? (args.indexOf('--config') !== -1 ? args[args.indexOf('--config') + 1] : undefined);

  const config = loadConfig(configPath);

  console.log(`\n  ARP Guard v${VERSION}`);
  console.log(`  Agent: ${config.agentName}`);
  console.log(`  Intelligence: ${config.intelligence?.enabled !== false ? '3-Layer (L0+L1+L2)' : 'L0+L1 only'}`);
  console.log(`  Budget: $${config.intelligence?.budgetUsd ?? 5.00}/month`);
  console.log(`  Monitors: ${Object.entries(config.monitors ?? {}).filter(([, v]) => (v as { enabled: boolean }).enabled).map(([k]) => k).join(', ') || 'all'}`);
  console.log();

  const arp = new AgentRuntimeProtection(config);

  // Graceful shutdown
  const shutdown = async () => {
    console.log('\n  Stopping ARP Guard...');
    await arp.stop();
    const status = arp.getStatus();
    console.log(`  Budget used: $${status.budget.spent} / $${status.budget.budget} (${status.budget.percentUsed}%)`);
    console.log(`  Total L2 calls: ${status.budget.totalCalls}`);
    console.log('  Stopped.\n');
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  await arp.start();
  console.log('  Monitoring... (press Ctrl+C to stop)\n');

  // Keep alive
  const keepAlive = setInterval(() => {}, 60000);
  keepAlive.unref();
}

async function showStatus(): Promise<void> {
  const config = loadConfig();
  const arp = new AgentRuntimeProtection(config);
  const status = arp.getStatus();

  console.log(`\n  ARP Guard Status`);
  console.log(`  Running: ${status.running}`);
  console.log(`  Budget: $${status.budget.spent} / $${status.budget.budget} (${status.budget.percentUsed}% used)`);
  console.log(`  L2 calls this period: ${status.budget.totalCalls}`);
  console.log(`  L2 calls this hour: ${status.budget.callsThisHour} / ${status.budget.maxCallsPerHour}`);
  console.log(`  Paused PIDs: ${status.pausedPids.length > 0 ? status.pausedPids.join(', ') : 'none'}`);
  console.log();
}

async function tailEvents(): Promise<void> {
  const config = loadConfig();
  const arp = new AgentRuntimeProtection(config);
  const events = arp.getEvents(parseInt(args[1]) || 20);

  if (events.length === 0) {
    console.log('\n  No events recorded yet.\n');
    return;
  }

  console.log(`\n  Last ${events.length} events:\n`);
  for (const event of events) {
    const severity = event.severity.toUpperCase().padEnd(8);
    const source = event.source.padEnd(10);
    const llm = event.classifiedBy === 'L2-llm' ? ' [LLM]' : '';
    console.log(`  ${event.timestamp}  ${severity}  ${source}  ${event.description.slice(0, 80)}${llm}`);
  }
  console.log();
}

async function showBudget(): Promise<void> {
  const config = loadConfig();
  const arp = new AgentRuntimeProtection(config);
  const status = arp.getStatus();
  const b = status.budget;

  console.log(`\n  ARP Intelligence Budget`);
  console.log(`  ─────────────────────────────`);
  console.log(`  Spent:     $${b.spent.toFixed(4)}`);
  console.log(`  Budget:    $${b.budget.toFixed(2)}`);
  console.log(`  Remaining: $${b.remaining.toFixed(4)}`);
  console.log(`  Used:      ${b.percentUsed}%`);
  console.log(`  ─────────────────────────────`);
  console.log(`  Total L2 calls: ${b.totalCalls}`);
  console.log(`  This hour:      ${b.callsThisHour} / ${b.maxCallsPerHour}`);
  console.log();
}

function showHelp(): void {
  console.log(`
  ARP Guard v${VERSION} — Agent Runtime Protection

  USAGE
    arp-guard <command> [options]

  COMMANDS
    start [--config <path>]   Start monitoring the agent
    stop                      Stop monitoring
    status                    Show current protection status
    tail [N]                  Show last N events (default: 20)
    budget                    Show LLM intelligence budget usage

  INTELLIGENCE
    ARP uses a 3-layer intelligence stack:
      L0: Rules (free)        Pattern matching on every event
      L1: Statistical (free)  Z-score anomaly detection
      L2: LLM-Assisted ($)    Micro-prompts to the agent's LLM

    99% of events never reach L2. Default budget: $5/month.
    Auto-detects Anthropic, OpenAI, or Ollama from environment.

  EXAMPLES
    arp-guard start                     Start with auto-detected config
    arp-guard start --config arp.yaml   Start with custom config
    arp-guard status                    Check budget and monitor status
    arp-guard tail 50                   Show last 50 events
    arp-guard budget                    Show intelligence spending
`);
}

main().catch((err) => {
  console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
