use clap::ValueEnum;

pub mod csv;

/// Supported format.
#[derive(Debug, Clone, ValueEnum)]
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
