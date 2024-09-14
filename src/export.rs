use clap::ValueEnum;

pub mod csv;

/// Supported format.
#[derive(Debug, Clone, ValueEnum)]
pub enum Format {
    Csv,
}
