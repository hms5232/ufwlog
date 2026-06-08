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
