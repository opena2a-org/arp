# Agent Runtime Protection (ARP)

Runtime security monitoring for AI agents. Detects anomalous behavior, enforces policies, and provides kill-switch capabilities.

## Features

- **3-Layer Intelligence Stack**: Rule-based (L0), statistical anomaly detection (L1), LLM-assisted assessment (L2)
- **Process Monitor**: Track child processes, detect high CPU, root execution
- **Network Monitor**: Track outbound connections, flag suspicious destinations
- **Filesystem Monitor**: Detect access to sensitive paths (.ssh, .aws, .gnupg)
- **Enforcement**: Log, alert, pause (SIGSTOP), kill (SIGTERM/SIGKILL)
- **Budget Controller**: Configurable monthly LLM spend limit ($5 default), hourly rate limiting
- **Offline-First**: JSONL local logging, no server required

## Installation

```bash
npm install @opena2a/arp
```

## Usage

### CLI

```bash
# Start monitoring
npx arp-guard start --config arp.yaml

# Check status
npx arp-guard status

# View recent events
npx arp-guard tail 20

# Check LLM budget
npx arp-guard budget
```

### Programmatic API

```typescript
import { AgentRuntimeProtection } from '@opena2a/arp';

const arp = new AgentRuntimeProtection({
  monitors: { process: true, network: true, filesystem: true },
  intelligence: { enabled: true, budget: { monthlyLimitUsd: 5.0 } },
});

await arp.start({ pid: process.pid, workingDir: process.cwd() });

// Later...
const status = arp.getStatus();
await arp.stop();
```

## Configuration

Create `arp.yaml` in your project root:

```yaml
monitors:
  process: true
  network: true
  filesystem: true

intelligence:
  enabled: true
  adapter: auto
  budget:
    monthlyLimitUsd: 5.0
    maxCallsPerHour: 20

enforcement:
  defaultAction: alert

logging:
  dir: .opena2a/arp
```

## License

Apache-2.0
