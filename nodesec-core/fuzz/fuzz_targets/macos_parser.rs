#![no_main]

use libfuzzer_sys::fuzz_target;
use nodesec_core::network::macos::MacOSNetworkMonitor;

fuzz_target!(|data: &[u8]| {
    if let Ok(line) = std::str::from_utf8(data) {
        let mut monitor = MacOSNetworkMonitor::new();
        let _ = monitor.parse_netstat_line_blocking(line, 1234567890, nodesec_core::models::NetworkProtocol::Tcp);
        let _ = monitor.parse_netstat_line_blocking(line, 1234567890, nodesec_core::models::NetworkProtocol::Udp);
    }
});

fuzz_target!(|data: &[u8]| {
    if let Ok(line) = std::str::from_utf8(data) {
        let _ = MacOSNetworkMonitor::parse_addr_static(line);
    }
});