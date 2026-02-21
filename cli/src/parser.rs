use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;
use ufwlog::UfwLog;

/// Get vector of UfwLog object from log file
pub fn get_ufwlog_vec(path: &str) -> Vec<UfwLog> {
    // make a spinner
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(150));
    pb.set_style(
        ProgressStyle::with_template("{spinner:.yellow} {msg}")
            .unwrap()
            .tick_strings(&[
                "😑 😑 😑 😑 😑",
                "🧐 😑 😑 😑 😑",
                "🤔 🧐 😑 😑 😑",
                "🤔 🤔 🧐 😑 😑",
                "🤔 🤔 🤔 🧐 😑",
                "🤔 🤔 🤔 🤔 🧐",
                "🤯 🤯 🤯 🤯 🤯",
                "🤯 🤯 🤯 🤯 🤯",
                "🥳 🥳 🥳 🥳 🥳",
            ]),
    );
    pb.set_message("Parsing...");

    // parse as UfwLog struct
    let ufw_log_vec = ufwlog::parser::get_ufwlog_vec(path);

    pb.finish_with_message("Parsed!");
    ufw_log_vec
}
