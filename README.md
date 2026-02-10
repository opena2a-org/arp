# ARP — Agent Runtime Protection

Runtime security monitoring for AI agents. Detects process spawns, network connections, and filesystem access in real-time with zero-latency application-level interception.

## Architecture

ARP uses two complementary detection layers:

**OS-Level Monitors** (polling) — detect activity via system tools (`ps`, `lsof`, `fs.watch`):
- `ProcessMonitor` — child process tracking, suspicious binary detection, CPU monitoring
- `NetworkMonitor` — outbound connection tracking with fallback chain: `lsof` → `ss` → `/proc/net/tcp` → `netstat`
- `FilesystemMonitor` — sensitive path access via recursive `fs.watch`

**Application-Level Interceptors** (zero-latency) — hook Node.js built-in modules:
- `ProcessInterceptor` — hooks `child_process.spawn/exec/execFile/fork`
- `NetworkInterceptor` — hooks `net.Socket.prototype.connect`
- `FilesystemInterceptor` — hooks `fs.readFile/writeFile/mkdir/unlink`

Interceptors fire **before** the I/O happens, with 100% accuracy and no kernel dependency.

**3-Layer Intelligence Stack:**
- **L0** — Rule-based classification (free, every event)
- **L1** — Statistical anomaly detection via z-score (free, flagged events)
- **L2** — LLM-assisted assessment with budget control (supports Anthropic, OpenAI, Ollama)

**Enforcement Actions:** `log` → `alert` → `pause` (SIGSTOP) → `kill` (SIGTERM/SIGKILL)

## Installation

```bash
npm install @opena2a/arp
```

## Quick Start

### As SDK

```typescript
import { AgentRuntimeProtection } from '@opena2a/arp';

const arp = new AgentRuntimeProtection({
  agentName: 'my-agent',
  monitors: {
    process: { enabled: true },
    network: { enabled: true, allowedHosts: ['api.example.com'] },
    filesystem: { enabled: true, watchPaths: ['/app/data'] },
  },
  interceptors: {
    process: { enabled: true },
    network: { enabled: true },
    filesystem: { enabled: true },
  },
});

// Subscribe to events
arp.onEvent((event) => {
  if (event.category === 'violation') {
    console.warn(`[ARP] ${event.severity}: ${event.description}`);
  }
});

await arp.start();

// ... your agent runs ...

await arp.stop();
```

### As CLI

```bash
npx arp-guard start                    # Start with auto-detected config
npx arp-guard start --config arp.yaml  # Start with custom config
npx arp-guard status                   # Show monitor status and budget
npx arp-guard tail 20                  # Show last 20 events
npx arp-guard budget                   # Show LLM spending
```

## Configuration

ARP auto-discovers config files: `arp.yaml` → `arp.yml` → `arp.json` → `.opena2a/arp.yaml`

```yaml
agentName: my-agent
agentDescription: Production agent with restricted capabilities
declaredCapabilities:
  - file read/write
  - HTTP requests

monitors:
  process:
    enabled: true
    intervalMs: 5000
  network:
    enabled: true
    intervalMs: 10000
    allowedHosts:
      - api.example.com
      - cdn.example.com
  filesystem:
    enabled: true
    watchPaths:
      - /app/data
    allowedPaths:
      - /app/data
      - /tmp

interceptors:
  process:
    enabled: true
  network:
    enabled: true
    allowedHosts:
      - api.example.com
  filesystem:
    enabled: true
    allowedPaths:
      - /app/data

rules:
  - name: critical-threat
    condition:
      category: threat
      minSeverity: critical
    action: kill
    requireLlmConfirmation: true

  - name: high-violation
    condition:
      category: violation
      minSeverity: high
    action: alert

intelligence:
  enabled: true
  adapter: anthropic
  budgetUsd: 5.0
  maxCallsPerHour: 20
  minSeverityForLlm: medium
```

## What Gets Detected

**Suspicious Binaries:** `curl`, `wget`, `nc`, `ncat`, `nmap`, `ssh`, `scp`, `python`, `perl`, `ruby`, `base64`, `socat`, `telnet`, `ftp`, `rsync`

**Suspicious Hosts:** `webhook.site`, `requestbin`, `ngrok.io`, `pipedream.net`, `hookbin.com`, `burpcollaborator`, `interact.sh`, `oastify.com`, `pastebin.com`, `transfer.sh`

**Sensitive Paths:** `.ssh`, `.aws`, `.gnupg`, `.kube`, `.config/gcloud`, `.docker/config.json`, `.npmrc`, `.pypirc`, `.git-credentials`, `wallet.json`, `.bashrc`, `.zshrc`, `.bash_profile`, `.profile`, `.gitconfig`, `.env`, `.netrc`, `.pgpass`

## Event Model

```typescript
interface ARPEvent {
  id: string;
  timestamp: string;
  source: 'process' | 'network' | 'filesystem';
  category: 'normal' | 'anomaly' | 'violation' | 'threat';
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  description: string;
  data: Record<string, unknown>;
  classifiedBy: 'L0-rules' | 'L1-statistical' | 'L2-llm';
}
```

## MITRE ATLAS Mapping

| Technique | Description | Detection |
|-----------|-------------|-----------|
| AML.T0046 | Unsafe ML Inference | Process spawn/exec monitoring |
| AML.T0057 | Data Leakage | Sensitive path + suspicious host detection |
| AML.T0024 | Exfiltration | Outbound connection tracking |
| AML.T0018 | Persistence | Shell config dotfile write detection |
| AML.T0029 | Denial of Service | CPU monitoring, budget exhaustion |
| AML.T0015 | Evasion | L1 anomaly baseline detection |
| AML.T0054 | Jailbreak | L2 LLM consistency assessment |

## Testing

```bash
npm test          # 18 unit tests
npm run build     # TypeScript compilation
```

For comprehensive security testing, see [OASB](https://github.com/opena2a-org/oasb) (182 tests across 42 files, mapped to MITRE ATLAS).

## License

Apache-2.0
