//! # ufwlog
//!
//! A library for parsing UFW (Uncomplicated Firewall) log files.

pub mod error;
pub mod export;
mod parser;
mod ufw_log;

pub use ufw_log::LoggedEvent;
pub use ufw_log::UfwLog;
