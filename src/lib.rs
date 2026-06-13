//! # ufwlog
//!
//! A library for parsing UFW (Uncomplicated Firewall) log files.
//!
//! ## Quick Start
//!
//! Parse a log file and filter blocked events from local:
//!
//! ```rust
//! use ufwlog::{UfwLog, LoggedEvent};
//!
//! let logs: Vec<UfwLog> = UfwLog::from_file("./ufw.log")?;
//!
//! let blocked = logs.iter()
//!     .filter(|log| log.event == LoggedEvent::Block)
//!     .filter(|log| log.src == "127.0.0.1")
//!     .collect::<Vec<_>>();
//! # Ok::<(), ufwlog::error::Error>(())
//! ```
//!
//! Or you want to a lazy iterator to handle each log:
//!
//! ```rust
//! use std::io::BufReader;
//! use ufwlog::{UfwLog, LoggedEvent};
//!
//! let reader = BufReader::new(std::fs::File::open("./ufw.log").unwrap());
//! let log_iters = UfwLog::from_buf_reader(reader);
//!
//! let blocked = log_iters
//!     .filter_map(|log| log.ok())
//!     .filter(|log| log.event == LoggedEvent::Block)
//!     .filter(|log| log.src == "127.0.0.1")
//!     .for_each(|log| println!("{}", log.dst));
//! # Ok::<(), ufwlog::error::Error>(())
//! ```

pub mod error;
pub mod export;
mod parser;
mod ufw_log;

pub use ufw_log::LoggedEvent;
pub use ufw_log::UfwLog;
