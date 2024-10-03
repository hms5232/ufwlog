use clap::{CommandFactory, Parser, Subcommand};

mod export;
mod parser;
mod ufw_log;

fn main() {
    // parse cli subcommand, arguments and flags
    let cli = Cli::parse();

    // handle subcommand
    match &cli.command {
        // export
        Some(SubCommands::Export {
            format,
            output_filename,
        }) => {
            // export with specific format
            match *format {
                Some(export::Format::Csv) => export::csv::convert(
                    parser::get_ufwlog_vec(cli.log_path.clone().unwrap().as_str()),
                    Some(output_filename.clone().unwrap().as_str()),
                )
                .unwrap(),
                _ => println!("Current not support other format"),
            }
        }
        _ => {
            // show help message
            Cli::command().print_help().unwrap();
        }
    }
}

#[derive(Parser)]
#[command(name = "ufwlog", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<SubCommands>,

    // "log_path" is a global flag for all subcommands, and the default value is dependent on OS.
    // if linux, default is read ufw log path
    #[cfg(target_os = "linux")]
    #[arg(
        short,
        long,
        value_name = "log_path",
        global = true,
        default_value = "/var/log/ufw.log"
    )]
    log_path: Option<String>,
    // else, read current directory "ufw.log" file
    #[cfg(not(target_os = "linux"))]
    #[arg(
        short,
        long,
        value_name = "log_path",
        global = true,
        default_value = "./ufw.log"
    )]
    log_path: Option<String>,
}

#[derive(Subcommand)]
enum SubCommands {
    /// Export UFW log file with other format
    Export {
        /// Which type to be export.
        #[arg(default_value = "csv")]
        format: Option<export::Format>,

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
