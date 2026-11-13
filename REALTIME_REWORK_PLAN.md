# nodesec Real-time Architecture Rework Plan

## Overview
Transform from static polling to real-time streaming architecture supporting:
1. **On-device mode**: Real-time local network monitoring with live UI updates
2. **Client-server mode**: Rule-based monitoring with WebSocket streaming from agents

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        NODESEC CORE                             │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐    ┌──────────────────┐                 │
│  │  NetworkMonitor  │    │  ThreatDetector  │                 │
│  │     Trait        │    │   (Rules + ML)   │                 │
│  └────────┬─────────┘    └────────┬─────────┘                 │
│           │                       │                            │
│    ┌──────┴──────┐      ┌────────┴────────┐                   │
│    ▼             ▼      ▼             ▼                      │
│ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐             │
│ │  Local  │ │ Remote  │ │ Rule    │ │ ML      │             │
│ │ Monitor │ │(WS)     │ │ Engine  │ │ Engine  │             │
│ └─────────┘ └─────────┘ └─────────┘ └─────────┘             │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
       ┌─────────────┐                 ┌─────────────┐
       │    TUI      │                 │    GUI      │
       │ (Real-time) │                 │ (Tauri +    │
       │  Updates    │                 │  D3.js)     │
       └─────────────┘                 └─────────────┘
```

---

## Mode Definitions

### Mode 1: On-Device (Real-time)
- **Source**: Local network monitor (Linux/macOS/Windows)
- **Frequency**: Continuous streaming (1-2 sec intervals)
- **UI**: Live updating connection table, threat alerts
- **Data Flow**: Local monitor → Channel → UI (no network)

### Mode 2: Client-Server (Rule-based)
- **Source**: Remote agents via WebSocket
- **Frequency**: Event-driven (connection events)
- **UI**: Network graph (D3.js), alert dashboard, rule management
- **Data Flow**: Agent → WebSocket → Server → UI

---

## Implementation Plan

### Phase 1: Core Network Layer
- [ ] WebSocket server (axum + tokio-tungstenite)
- [ ] NetworkMonitor trait with Local/Remote implementations
- [ ] ConnectionHandler with streaming support
- [ ] ThreatDetector integration

### Phase 2: TUI Rework
- [ ] Real-time network tab with live updates
- [ ] Mode selector (On-Device / Client-Server)
- [ ] Live connection table with threat highlighting
- [ ] Alert notifications

### Phase 3: GUI Rework (Tauri)
- [ ] Tauri app with WebSocket client
- [ ] D3.js force-directed network graph
- [ ] Real-time threat visualization
- [ ] Mode switching UI

### Phase 4: Client-Server Protocol
- [ ] Agent binary (lightweight monitor)
- [ ] Server API (REST + WebSocket)
- [ ] Rule management API
- [ ] Agent registration/auth

---

## Key Data Structures

```rust
// Real-time connection event
struct ConnectionEvent {
    timestamp: u64,
    pid: u32,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: NetworkProtocol,
    process_name: String,
    process_path: Option<String>,
    command_line: Option<String>,
    user: Option<String>,
    threat_score: u8,
    is_suspicious: bool,
}

// Network monitor modes
enum MonitorMode {
    OnDevice,           // Real-time local
    ClientServer,       // WebSocket from agents
}

// WebSocket messages
enum WSMessage {
    ConnectionEvent(ConnectionEvent),
    ThreatAlert(ThreatAlert),
    RuleUpdate(RuleSet),
    AgentStatus(AgentInfo),
    Heartbeat,
}
```

---

## TUI Layout (Reworked)

```
┌─────────────────────────────────────────────────────────────┐
│ NODESEC - [On-Device ▼]  [Live]  [Alerts: 3]  [⚙]          │
├─────────────────────────────────────────────────────────────┤
│ Connections (Live)                    │ Details             │
│ ┌──────────────────────────────────┐  │ ┌────────────────┐ │
│ │ PID  Process    Src→Dst       Threat │  │ Process: chrome │ │
│ │ 1234 chrome   192.168.1.5:54321   🟢   │  │ PID: 1234       │ │
│ │ 1235 curl     10.0.0.1:22       🔴   │  │ Threat: 85/100  │ │
│ │ 1236 ssh      192.168.1.10:22   🟡   │  │ Connections: 12 │ │
│ └──────────────────────────────────┘  │ └────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ [←/→ Tabs] [Space: Pause] [F: Filter] [A: Alerts] [Q: Quit] │
└─────────────────────────────────────────────────────────────┘
```

## GUI Layout (Tauri + D3.js)

```
┌─────────────────────────────────────────────────────────────┐
│ NODESEC                                    [On-Device ▼]   │
├──────────────┬──────────────────────────────────────────────┤
│              │                                              │
│  Dashboard   │     Force-Directed Network Graph (D3.js)     │
│              │                                              │
│  ▸ Summary   │     ● chrome (12 conn) ── 🟢 ── 8.8.8.8      │
│  ▸ Alerts    │         │                                      │
│  ▸ Network   │         ├── 🔴 curl ──── 10.0.0.1:22         │
│  ▸ Rules     │         └── 🟡 ssh ────── 192.168.1.10:22    │
│  ▸ Agents    │                                              │
│  ▸ Settings  │  [Pause] [Zoom] [Filter] [Export]            │
├──────────────┴──────────────────────────────────────────────┤
│ Alert Panel: 🔴 Critical: curl to suspicious IP (10.0.0.1)  │
└─────────────────────────────────────────────────────────────┘
```