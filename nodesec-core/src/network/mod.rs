//! Cross-platform network monitoring with real-time streaming

pub mod common;
pub mod linux;
pub mod macos;
pub mod windows;
pub mod handler;
pub mod server;

pub use common::{ConnectionEvent, NetworkMonitor};
pub use handler::ConnectionHandler;
pub use server::{NetworkServer, ServerConfig};

// Re-export key types from models
pub use crate::models::{
    NetworkConnection, NetworkProtocol, Platform, MonitorMode,
    WSMessage, AgentInfo, RuleSet, ThreatAlert, DetectionRule,
};