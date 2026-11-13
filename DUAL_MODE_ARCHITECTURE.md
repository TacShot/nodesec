# nodesec Dual-Mode Architecture

## Overview
Two distinct operational modes with separate entry points:

| Mode | Purpose | Entry Point | UI |
|------|---------|-------------|----|
| **Network** | Real-time network monitoring | `nodesec net` | Live TUI/GUI |
| **Audit** | Static security audit | `nodesec audit` | TUI/GUI/CLI |

---

## Entry Points

```
nodesec
├── net              # Network/Connections mode
│   ├── live         # On-device real-time
│   ├── server       # Client-server mode
│   └── agents       # Agent management
│
├── audit            # Static Audit mode (hyntel legacy)
│   ├── run          # Run audit
│   ├── report       # View reports
│   └── remediate    # Generate remediation
│
├── report           # Unified report viewer
└── config           # Configuration management
```

---

## Network Mode (`nodesec net`)

### Subcommands
```
nodesec net live          # On-device real-time monitoring
nodesec net server        # Start WebSocket server (client-server)
nodesec net agents        # Manage connected agents
nodesec net rules         # Manage detection rules
nodesec net status        # Show connection status
```

### Modes

#### On-Device (`net live`)
- Real-time local network monitoring
- Live TUI/GUI with streaming updates
- Threat detection with local rules + ML
- No external dependencies

#### Client-Server (`net server`)
- WebSocket server for agent connections
- Rule distribution to agents
- Centralized threat dashboard
- Agent registration/authentication

### Agents (`net agents`)
```
nodesec net agents list         # List connected agents
nodesec net agents register     # Register new agent
nodesec net agents revoke       # Revoke agent access
nodesec net agents logs <id>    # View agent logs
```

---

## Audit Mode (`nodesec audit`)

### Subcommands (hyntel legacy)
```
nodesec audit run           # Run security audit
nodesec audit run --interactive
nodesec audit run --format json
nodesec audit report        # View last report
nodesec audit report <id>   # View specific report
nodesec audit remediate     # Generate remediation script
nodesec audit config        # Configure audit options
```

### Features (hyntel legacy)
- 27 security checks (Linux/macOS/Windows)
- CVE enrichment (NIST NVD API)
- Application inventory
- Process assessment
- AD scanning
- Log collection
- Remediation scripts
- Compliance mapping (ISO27001, HIPAA, PCI-DSS)

---

## Shared Infrastructure

### Report System (Unified)
- Both modes write to `~/.local/share/nodesec/reports/`
- Format: `nodesec-{mode}-{platform}-{YYYY-MM-DD}-{HH-MM-SS-AM/PM}/`
- Formats: txt, json, csv

### Configuration (Unified)
- `~/.config/nodesec/config.toml`
- Separate sections for `[network]` and `[audit]`

---

## Implementation Priority

### Phase 1: Network Mode Core
1. Real-time network monitor with streaming
2. WebSocket server for client-server
3. TUI with live network tab
4. Tauri GUI with D3.js graph

### Phase 2: Audit Mode Integration
1. Preserve all hyntel functionality
2. Unified report system
3. Shared config

### Phase 3: CLI Unification
1. Dual-mode CLI entry point
2. Shared config/flags
3. Unified help

---

## TUI Layout (Network Mode)

```
┌─────────────────────────────────────────────────────────────┐
│ NODESEC NETWORK  [Live ▼]  [● Connected]  [Alerts: 3]  [⚙]  │
├─────────────────────────────────────────────────────────────┤
│ Connections (Live)                    │ Details             │
│ ┌──────────────────────────────────┐  │ ┌────────────────┐ │
│ │ PID  Process    Src→Dst       T  │  │ Process: chrome │ │
│ │ 1234 chrome   192.168.1.5:54321 🟢 │  │ PID: 1234       │ │
│ │ 1235 curl     10.0.0.1:22       🔴 │  │ Threat: 85/100  │ │
│ │ 1236 ssh      192.168.1.10:22   🟡 │  │ Connections: 12 │ │
│ └──────────────────────────────────┘  │ └────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ [←/→ Tabs] [Space: Pause] [F: Filter] [A: Alerts] [Q: Quit] │
└─────────────────────────────────────────────────────────────┘
```

---

## GUI Layout (Network Mode - Tauri + D3.js)

```
┌─────────────────────────────────────────────────────────────┐
│ NODESEC NETWORK                                    [Live ▼] │
├──────────────┬──────────────────────────────────────────────┤
│              │                                              │
│  Dashboard   │     Force-Directed Network Graph (D3.js)     │
│              │                                              │
│  ▸ Live      │     ● chrome (12 conn) ── 🟢 ── 8.8.8.8      │
│  ▸ Alerts    │         │                                      │
│  ▸ Network   │         ├── 🔴 curl ──── 10.0.0.1:22         │
│  ▸ Rules     │         └── 🟡 ssh ────── 192.168.1.10:22    │
│  ▸ Agents    │                                              │
│  ▸ Settings  │  [Pause] [Zoom] [Filter] [Export]            │
├──────────────┴──────────────────────────────────────────────┤
│ Alert Panel: 🔴 Critical: curl to suspicious IP (10.0.0.1)  │
└─────────────────────────────────────────────────────────────┘
```

---

## TUI Layout (Audit Mode)

```
┌─────────────────────────────────────────────────────────────┐
│ NODESEC AUDIT  [Configure ▼]  [Run]  [Reports]  [⚙]        │
├─────────────────────────────────────────────────────────────┤
│ ▸ Run Audit    │ Configure and run security audit          │
│ ▸ Configure    │ Set scan options and preferences          │
│ ▸ Last Report  │ View most recent scan results             │
│ ▸ Output Dir   │ Manage output directory                   │
│ ▸ Help         │ Show keyboard shortcuts                   │
│ ▸ Exit         │ Quit application                          │
└─────────────────────────────────────────────────────────────┘
```

---

## Configuration Structure

```toml
# ~/.config/nodesec/config.toml

[general]
data_dir = "~/.local/share/nodesec"
log_level = "info"

[network]
mode = "live"                    # "live" or "server"
interface = "auto"               # network interface
refresh_interval = 2             # seconds
max_connections = 10000
retention_minutes = 5

[network.server]
bind = "0.0.0.0:8080"
tls = false
cert_path = ""
key_path = ""

[network.rules]
enable_ml = true
threat_threshold = 50
custom_rules = []

[audit]
include_cves = true
cve_limit = 3
generate_remediation = true
scan_apps = true
app_limit = 25
collect_logs = false
log_hours = 24
scan_ad = false
standards = ["ISO27001", "HIPAA", "PCI_DSS"]
output_dir = "artifacts"
save_to_desktop = true
```

---

## CLI Entry Point Structure

```rust
// src/main.rs
#[derive(Parser)]
#[command(name = "nodesec", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Network monitoring mode
    Net(NetCommands),
    /// Security audit mode
    Audit(AuditCommands),
    /// View reports
    Report(ReportCommands),
    /// Configuration
    Config(ConfigCommands),
}

#[derive(Subcommand)]
enum NetCommands {
    Live(LiveArgs),
    Server(ServerArgs),
    Agents(AgentCommands),
    Rules(RuleCommands),
    Status,
}

#[derive(Subcommand)]
enum AuditCommands {
    Run(RunArgs),
    Report(ReportArgs),
    Remediate(RemediateArgs),
    Config(ConfigArgs),
}
```

---

## Migration Path

1. **Keep existing audit code** in `nodesec-core` as-is
2. **Add network module** as new `nodesec-core/network/`
3. **Create `nodesec-net` crate** for network-specific logic
4. **Update main binary** to dispatch to correct mode
5. **Preserve all existing tests** for audit functionality