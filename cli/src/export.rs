use clap::ValueEnum;

pub mod csv;

#[derive(Debug)]
/// The config and option for export
pub struct Config {
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

/// Export format that CLI support
#[derive(ValueEnum, Debug, Clone, PartialEq)]
pub(crate) enum ExportFormat {
    Csv,
}

impl From<ExportFormat> for ufwlog::ExportFormat {
    fn from(value: ExportFormat) -> Self {
        match value {
            ExportFormat::Csv => ufwlog::ExportFormat::Csv,
        }
    }
}
