#[cfg(feature = "cli")]
use clap::ValueEnum;

pub mod csv;

/// Supported export formats
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "cli", derive(ValueEnum))]
pub enum Format {
    Csv,
}

impl Format {
    /// Get the extension of this format.
    pub fn get_extension(&self) -> &str {
        match self {
            Format::Csv => "csv",
        }
    }
}
