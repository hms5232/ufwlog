use clap::{Parser, Subcommand, ValueEnum};
use indicatif::{ProgressBar, ProgressStyle};

mod export;
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
            // progress bar
            let pb_style = ProgressStyle::with_template("{msg} {wide_bar} {pos}/{len}").unwrap();
            let parser_pb = ProgressBar::new(log_by_line.len() as u64)
                .with_style(pb_style)
                .with_message("Parse ufw log ...");
            // parsing
            for i in 0..log_by_line.len() {
                let map = parser::to_hashmap(&log_by_line[i]);
                ufw_log_map.push(map);
                parser_pb.inc(1);
            }
            parser_pb.finish_with_message("Parse ufw log success.");

            // export with specific format
            match *format {
                Some(export::Format::Csv) => export::csv::convert(
                    ufw_log_map,
                    Some(output_filename.clone().unwrap().as_str()),
                )
                .unwrap(),
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
        format: Option<export::Format>,

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
