# nodesec-net-gui Native egui/eframe Implementation Plan

## Overview
Replace the Tauri + React/D3.js web wrapper with a pure native Rust egui/eframe GUI for network monitoring. This eliminates the web attack surface and provides a true native experience.

## Architecture

```
nodesec-net-gui (native egui/eframe)
├── src/
│   ├── main.rs          # Entry point + App struct + UI rendering
│   ├── monitor.rs       # Background monitoring task
│   ├── state.rs         # Shared state (connections, alerts, stats)
│   └── ui/
│       ├── connections.rs   # Connections table view
│       ├── alerts.rs        # Alerts panel view
│       ├── statistics.rs    # Statistics dashboard
│       └── settings.rs      # Settings panel
```

## Key Components

### 1. Shared State (`state.rs`)
- `Arc<Mutex<Vec<ConnectionItem>>>` - connections list
- `Arc<Mutex<Vec<String>>>` - alerts
- `Arc<Mutex<ConnectionStats>>` - statistics
- `Arc<tokio::sync::Mutex<Option<Box<dyn NetworkMonitor>>>>` - platform monitor
- `Arc<Mutex<bool>>` - monitoring flag

### 2. Background Monitor (`monitor.rs`)
- Spawns tokio task for platform-specific monitoring
- Calls `scan_once()` every 2 seconds
- Drains events from monitor and pushes to shared state
- Handles start/stop lifecycle

### 3. UI Components (`ui/`)
- **Connections**: Table with PID, Process, Proto, Source, Dest, Threat, Score
- **Alerts**: Scrollable list with color-coded severity
- **Statistics**: Cards for Total/Active/Suspicious/Critical + threat distribution
- **Settings**: Platform info, interval, thresholds, retention

### 4. Main App (`main.rs`)
- eframe::App implementation
- Top panel: Header + Tabs
- Bottom panel: Footer with shortcuts
- Central panel: Tab content
- Polls shared state for updates

## Color Palette (7 colors only)
- White (#FFFFFF) - Primary text
- Black (#000000) - Background
- Gray (#888888) - Secondary text
- Green (#00FF00) - Safe/Pass
- Yellow (#FFFF00) - Warning/Low
- Red (#FF0000) - Critical/High
- Orange (#FFA500) - Accent/Headers

## Data Flow
```
Platform Monitor (Linux/macOS/Windows) 
    → scan_once() every 2s
    → drain_events() 
    → Shared State (Arc<Mutex>)
    → UI polls state on each frame
    → Render via egui widgets
```

## Implementation Order
1. `state.rs` - Shared state structures
2. `monitor.rs` - Background monitoring task
3. `ui/` components - Reusable UI functions
4. `main.rs` - App entry point + main UI loop
5. Test build and run