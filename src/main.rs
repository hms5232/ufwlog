use clap::{Parser, Subcommand, ValueEnum};

mod csv;
mod parser;

fn main() {
    // parse cli subcommand, arguments and flags
    let cli = Cli::parse();

    // handle subcommand
    match &cli.command {
        // export
        Some(SubCommands::Export {
            format,
            log_path,
            output_filename,
        }) => {
            let mut ufw_log_map = vec![];
            let log_by_line = parser::read_lines(log_path.clone().unwrap().as_str());
            for i in 0..log_by_line.len() {
                let map = parser::to_hashmap(&log_by_line[i]);
                ufw_log_map.push(map);
            }

            // export with specific format
            match *format {
                Some(ExportFormat::Csv) => {
                    csv::convert(ufw_log_map, Some(output_filename.clone().unwrap().as_str()))
                        .unwrap()
                }
                _ => println!("Current not support other format"),
            }
        }
        _ => {
            todo!("Default behavior.")
        }
    }
}

#[derive(Parser)]
#[command(name = "ufwlog", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<SubCommands>,
}

#[derive(Subcommand)]
enum SubCommands {
    /// Export UFW log file with other format
    Export {
        /// Which type to be export.
        #[arg(default_value = "csv")]
        format: Option<ExportFormat>,

        // if linux, default is read ufw log path
        // else, read current directory "ufw.log" file
        #[cfg(target_os = "linux")]
        /// Specify a log file.
        #[arg(
            short,
            long,
            value_name = "log_path",
            default_value = "/var/log/ufw.log"
        )]
        log_path: Option<String>,
        #[cfg(not(target_os = "linux"))]
        /// Specify a log file.
        #[arg(short, long, value_name = "log_path", default_value = "./ufw.log")]
        log_path: Option<String>,

        /// Specify output path and filename.
        #[arg(
            short,
            long = "output",
            value_name = "filename",
            default_value = "ufwlog"
        )]
        output_filename: Option<String>,
    },
}

/// Supported export format.
#[derive(Debug, Clone, ValueEnum)]
enum ExportFormat {
    Csv,
}
