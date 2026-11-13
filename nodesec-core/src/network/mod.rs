//! Cross-platform network monitoring abstraction

pub mod linux;
pub mod macos;
pub mod windows;
pub mod handler;
pub mod common;

pub use common::{ConnectionEvent, NetworkMonitor};
pub use handler::ConnectionHandler;