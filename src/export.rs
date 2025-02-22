use clap::ValueEnum;

pub mod csv;

/// Supported format.
#[derive(Debug, Clone, ValueEnum)]
pub enum Format {
    Csv,
}

#[derive(Debug)]
/// The config and option for export
pub(crate) struct Config {
    output_filename: String,
    overwrite: bool,
}

impl Config {
    pub fn new(output_filename: &Option<String>, overwrite: bool) -> Self {
        let filename = match output_filename {
            Some(t) => t.clone(),
            None => String::from("ufwlog"), // default output filename
        };
        Self {
            output_filename: filename,
            overwrite,
        }
    }
}

impl Format {
    /// Get the extension of this format.
    fn get_extension(&self) -> &str {
        match self {
            Format::Csv => "csv",
        }
    }
}
