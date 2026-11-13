#![no_main]

use libfuzzer_sys::fuzz_target;
use nodesec_core::threat::ThreatDetector;
use nodesec_core::models::NetworkConnection;

fuzz_target!(|data: &[u8]| {
    let mut detector = ThreatDetector::new();
    if let Ok(conn) = serde_json::from_slice::<NetworkConnection>(data) {
        let _ = detector.analyze(&conn);
    }
});

fuzz_target!(|data: &[u8]| {
    // Fuzz threat score calculation with random connection data
    let mut detector = ThreatDetector::new();
    let conn = NetworkConnection {
        timestamp: 1234567890,
        pid: 1234,
        src_ip: "192.168.1.1".parse().unwrap(),
        dst_ip: "10.0.0.1".parse().unwrap(),
        src_port: 12345,
        dst_port: 80,
        protocol: nodesec_core::models::NetworkProtocol::Tcp,
        process_name: "test".to_string(),
        process_path: Some("/usr/bin/test".to_string()),
        command_line: Some("test arg".to_string()),
        user: Some("user".to_string()),
        threat_score: 0,
        is_suspicious: false,
    };
    let _ = detector.analyze(&conn);
});

fuzz_target!(|data: &[u8]| {
    // Fuzz the ML anomaly detection
    let mut detector = ThreatDetector::new();
    // Train with some data first
    for i in 0..10 {
        let conn = NetworkConnection {
            timestamp: 1234567890 + i,
            pid: 1000 + i,
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 12345 + i as u16,
            dst_port: 80,
            protocol: nodesec_core::models::NetworkProtocol::Tcp,
            process_name: "test".to_string(),
            process_path: Some("/usr/bin/test".to_string()),
            command_line: Some("test".to_string()),
            user: Some("user".to_string()),
            threat_score: (i * 10) as u8,
            is_suspicious: i > 5,
        };
        let _ = detector.analyze(&conn);
    }
    // Now test with fuzz data
    if let Ok(conn) = serde_json::from_slice::<NetworkConnection>(data) {
        let _ = detector.analyze(&conn);
    }
});