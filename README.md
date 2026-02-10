> **[OpenA2A](https://opena2a.org)**: [AIM](https://opena2a.org/docs) · [HackMyAgent](https://hackmyagent.com) · [OASB](https://oasb.ai) · [ARP](https://github.com/opena2a-org/arp) · [Secretless](https://github.com/opena2a-org/secretless-ai) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent)

# ARP — Agent Runtime Protection

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests](https://img.shields.io/badge/tests-18%20passing-brightgreen)](https://github.com/opena2a-org/arp)
[![OASB](https://img.shields.io/badge/OASB-182%20tests-teal)](https://github.com/opena2a-org/oasb)

**Detect. Intercept. Enforce.**

Runtime security monitoring for AI agents. Detects process spawns, network connections, and filesystem access in real-time — with zero-latency application-level interception that fires *before* the I/O happens.

[OpenA2A](https://opena2a.org) | [OASB Benchmark](https://github.com/opena2a-org/oasb) | [MITRE ATLAS Mapping](#mitre-atlas-mapping)

---

## Table of Contents

- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Detection Coverage](#detection-coverage)
- [Event Model](#event-model)
- [MITRE ATLAS Mapping](#mitre-atlas-mapping)
- [Testing](#testing)
- [License](#license)

---

## Quick Start

```bash
npm install @opena2a/arp
```

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

---

## Architecture

ARP uses two complementary detection layers plus a 3-layer intelligence stack.

### Detection Layers

| Layer | Mechanism | Latency | Coverage |
|-------|-----------|---------|----------|
| **OS-Level Monitors** | Polling (`ps`, `lsof`, `fs.watch`) | 200–1000ms | Catches everything on the system |
| **Application Interceptors** | Node.js module hooks | <1ms | Fires before I/O, 100% accuracy |

<details>
<summary>OS-Level Monitors</summary>

| Monitor | What It Detects |
|---------|-----------------|
| `ProcessMonitor` | Child process tracking, suspicious binary detection, CPU monitoring |
| `NetworkMonitor` | Outbound connections with fallback chain: `lsof` → `ss` → `/proc/net/tcp` → `netstat` |
| `FilesystemMonitor` | Sensitive path access via recursive `fs.watch` |

</details>

<details>
<summary>Application-Level Interceptors</summary>

| Interceptor | Hooks | What It Catches |
|-------------|-------|-----------------|
| `ProcessInterceptor` | `child_process.spawn/exec/execFile/fork` | All child process creation |
| `NetworkInterceptor` | `net.Socket.prototype.connect` | All outbound TCP connections |
| `FilesystemInterceptor` | `fs.readFile/writeFile/mkdir/unlink` | All filesystem I/O |

Interceptors fire **before** the operation executes. No kernel dependency required.

</details>

### Intelligence Stack

| Layer | Method | Cost | When |
|-------|--------|------|------|
| **L0** | Rule-based classification | Free | Every event |
| **L1** | Z-score anomaly detection | Free | Flagged events |
| **L2** | LLM-assisted assessment | Budget-controlled | Escalated events |

L2 supports Anthropic, OpenAI, and Ollama adapters with per-hour call limits and USD budget caps.

### Enforcement Actions

```
log → alert → pause (SIGSTOP) → kill (SIGTERM/SIGKILL)
```

Each action is configurable per-rule with optional LLM confirmation before enforcement.

---

## Configuration

ARP auto-discovers config files: `arp.yaml` → `arp.yml` → `arp.json` → `.opena2a/arp.yaml`

<details>
<summary>Full configuration example</summary>

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

</details>

---

## Detection Coverage

<details>
<summary>Suspicious binaries (15)</summary>

`curl`, `wget`, `nc`, `ncat`, `nmap`, `ssh`, `scp`, `python`, `perl`, `ruby`, `base64`, `socat`, `telnet`, `ftp`, `rsync`

</details>

<details>
<summary>Suspicious hosts (10)</summary>

`webhook.site`, `requestbin`, `ngrok.io`, `pipedream.net`, `hookbin.com`, `burpcollaborator`, `interact.sh`, `oastify.com`, `pastebin.com`, `transfer.sh`

</details>

<details>
<summary>Sensitive paths (18)</summary>

`.ssh`, `.aws`, `.gnupg`, `.kube`, `.config/gcloud`, `.docker/config.json`, `.npmrc`, `.pypirc`, `.git-credentials`, `wallet.json`, `.bashrc`, `.zshrc`, `.bash_profile`, `.profile`, `.gitconfig`, `.env`, `.netrc`, `.pgpass`

</details>

---

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

---

## MITRE ATLAS Mapping

| Technique | ID | Detection |
|-----------|----|-----------|
| Unsafe ML Inference | AML.T0046 | Process spawn/exec monitoring |
| Data Leakage | AML.T0057 | Sensitive path + suspicious host detection |
| Exfiltration | AML.T0024 | Outbound connection tracking |
| Persistence | AML.T0018 | Shell config dotfile write detection |
| Denial of Service | AML.T0029 | CPU monitoring, budget exhaustion |
| Evasion | AML.T0015 | L1 anomaly baseline detection |
| Jailbreak | AML.T0054 | L2 LLM consistency assessment |

---

## Testing

```bash
npm test          # 18 unit tests
npm run build     # TypeScript compilation
```

For comprehensive security testing, see [OASB](https://github.com/opena2a-org/oasb) — 182 attack scenarios across 42 test files mapped to MITRE ATLAS.

---

## License

Apache-2.0

---

## OpenA2A Ecosystem

| Project | Description | Install |
|---------|-------------|---------|
| [**AIM**](https://github.com/opena2a-org/agent-identity-management) | Agent Identity Management -- identity and access control for AI agents | `pip install aim-sdk` |
| [**HackMyAgent**](https://github.com/opena2a-org/hackmyagent) | Security scanner -- 147 checks, attack mode, auto-fix | `npx hackmyagent secure` |
| [**OASB**](https://github.com/opena2a-org/oasb) | Open Agent Security Benchmark -- 182 attack scenarios | `npm install @opena2a/oasb` |
| [**ARP**](https://github.com/opena2a-org/arp) | Agent Runtime Protection -- process, network, filesystem monitoring | `npm install @opena2a/arp` |
| [**Secretless AI**](https://github.com/opena2a-org/secretless-ai) | Keep credentials out of AI context windows | `npx secretless-ai init` |
| [**DVAA**](https://github.com/opena2a-org/damn-vulnerable-ai-agent) | Damn Vulnerable AI Agent -- security training and red-teaming | `docker pull opena2a/dvaa` |
