#![no_main]

use libfuzzer_sys::fuzz_target;
use nodesec_core::network::linux::LinuxNetworkMonitor;

fuzz_target!(|data: &[u8]| {
    if let Ok(line) = std::str::from_utf8(data) {
        let _ = LinuxNetworkMonitor::parse_proc_net_line_static(line, false);
        let _ = LinuxNetworkMonitor::parse_proc_net_line_static(line, true);
    }
});

fuzz_target!(|data: &[u8]| {
    if let Ok(content) = std::str::from_utf8(data) {
        // Fuzz the /proc/net/tcp format
        let _ = LinuxNetworkMonitor::parse_proc_net_tcp_static(content);
    }
});

fuzz_target!(|data: &[u8]| {
    if let Ok(content) = std::str::from_utf8(data) {
        // Fuzz the /proc/net/udp format
        let _ = LinuxNetworkMonitor::parse_proc_net_udp_static(content);
    }
});