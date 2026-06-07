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

    /// Converts multiple log entries into formatted strings.
    ///
    /// Returns one string per entry, without any header, footer or other metadata.
    /// Use [export()](self::Export::export) if you need a file-ready output.
    fn convert_vec(&self, logs: &[crate::UfwLog]) -> Result<Vec<String>, Error>;

    /// Converts multiple log entries into a complete, file-ready output.
    ///
    /// Unlike [convert_vec()](self::Export::convert_vec), the output may include format-specific metadata such as a CSV header row.
    fn export(&self, logs: &[crate::UfwLog]) -> Result<Vec<String>, Error>;
}
