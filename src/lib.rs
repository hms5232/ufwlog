//! # ufwlog
//!
//! A library for parsing UFW (Uncomplicated Firewall) log files.
//!
//! ## Quick Start
//!
//! The essential part is the [UfwLog] struct.
//!
//! ```rust
//! use std::str::FromStr;
//! use ufwlog::UfwLog;
//!
//! // parse a log string then get a UfwLog struct
//! let log_str = "Jan 16 02:13:52 103213020 kernel: [3601090.569259] [UFW AUDIT] IN= OUT=lo SRC=127.0.0.1 DST=127.0.0.1 LEN=84 TOS=0x00 PREC=0x00 TTL=64 ID=33539 DF PROTO=ICMP TYPE=8 CODE=0 ID=10289 SEQ=1";
//! let log: UfwLog = UfwLog::from_str(log_str).unwrap();
//! // the struct fields is from log
//! assert_eq!(log.month, 1);
//! assert_eq!(log.day, 16);
//! assert_eq!(log.src.to_string(), "127.0.0.1")
//! // and you can do some something else what you want with the struct
//! ```
//!
//! Mostly usage is not a single record, it is a file contains many records.
//!
//! This crate also provide [UfwLog::from_file] to parse whole log file:
//!
//! ```rust, no_run
//! use ufwlog::{UfwLog, UfwPolicy};
//!
//! // parse whole log file
//! // you will get a vector of UfwLogs
//! let logs: Vec<UfwLog> = UfwLog::from_file("./ufw.log")?;
//!
//! // after parsing, you can do something else
//! // for example, filter blocked record and port is 22
//! let blocked: Vec<&UfwLog> = logs.iter()
//!     .filter(|log| log.policy == UfwPolicy::Block)
//!     .filter(|log| log.dpt.unwrap_or(0) == 22)
//!     .collect::<Vec<_>>();
//! # Ok::<(), ufwlog::error::Error>(())
//! ```
//!
//! Or you want to a lazy iterator to handle each log:
//!
//! ```rust, no_run
//! use std::io::BufReader;
//! use ufwlog::{UfwLog, UfwPolicy};
//!
//! let reader = BufReader::new(std::fs::File::open("./ufw.log")?);
//! let log_iters = UfwLog::from_buf_reader(reader);
//!
//! log_iters
//!     .filter_map(|log| log.ok())
//!     .filter(|log| log.policy == UfwPolicy::Block) // filter blocked record
//!     .filter(|log| log.src.to_string() == "127.0.0.1") // filter source is local
//!     .for_each(|log| println!("{}", log.dst)); // print destination
//! # Ok::<(), ufwlog::error::Error>(())
//! ```

pub mod error;
pub mod export;
mod parser;
mod ufw_log;

pub use ufw_log::Policy as UfwPolicy;
pub use ufw_log::Time;
pub use ufw_log::UfwLog;
