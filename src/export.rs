//! Traits and implementations for exporting UFW logs into various formats.
//!
//! This module provides the interface for exporting UFW logs into a specific format.
//! You can use the built-in exporter or implement the [`Export`] trait to support new format.
//!
//! ## Quick Start
//!
//! ```rust
//! let logs = ufwlog::UfwLog::from_file("./ufw.log")?;
//! let target = "csv";
//!
//! let exporter: Box<dyn ufwlog::export::Export> = match target {
//!     "csv" => Box::new(ufwlog::export::csv::Exporter),
//!     _ => unimplemented!(),
//! };
//! // write to stdout
//! let stdout = std::io::stdout();
//! let mut writer = std::io::BufWriter::new(stdout.lock());
//! exporter.export(&logs, &mut writer)?;
//!
//! # Ok::<(), ufwlog::error::Error>(())
//! ```

use crate::error::Error;

pub mod csv;

/// Supported export formats
#[derive(Debug, Clone, PartialEq)]
pub enum Format {
    Csv,
}

/// Defines the interface for exporting UFW logs into a specific format.
///
/// # Implementing
///
/// Types that implement this trait should be zero-size structs, as they
/// typically hold no state.
pub trait Export {
    /// Get the extension of this format. (e.g. csv, json)
    fn get_extension(&self) -> &'static str;

    /// convert a single log entry into a formatted string.
    fn convert(&self, log: &crate::UfwLog) -> Result<String, Error>;

    /// Export log entries into a writer.
    fn export(&self, logs: &[crate::UfwLog], writer: &mut dyn std::io::Write) -> Result<(), Error>;
}
