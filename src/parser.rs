//! A parser for ufw log file.

use crate::ufw_log::UfwLog;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::fs;
use std::time::Duration;

/// Read file and get content line by line
///
/// # Panic
///
/// If the file read failed, it will panic directly.
///
/// # Example
///
/// Consider we have a file and contain below text:
/// > parser
///
/// > read lines
///
/// then use this function to get file content:
///
/// ```
/// read_lines(file_path)
/// ```
///
/// will return
///
/// ```
/// vec![String::from("parser"), String::from("read lines")]
/// ```
pub fn read_lines(path: &str) -> Vec<String> {
    // read log file
    let file = fs::read_to_string(path);
    if file.is_err() {
        panic!("Error occur when trying to read file.");
    }

    file.unwrap().lines().map(String::from).collect()
}

/// Split log record by space, and filter empty element(s).
pub fn split_by_space(log: &String) -> Vec<&str> {
    log.split(" ").filter(|&x| !x.is_empty()).collect()
}

/// convert log record string to hashmap
pub fn to_hashmap(log: &String) -> HashMap<&str, String> {
    let split_log = split_by_space(log);
    let mut associative = HashMap::new();

    // add origin record
    associative.insert("origin", log.to_owned());
    // handle each fields
    for (index, value) in split_log.iter().enumerate() {
        // handle record has equal symbol
        if value.contains("=") {
            let key_and_value: Vec<&str> = value.split("=").collect();
            associative.insert(
                key_and_value.get(0).unwrap().trim(),
                key_and_value.get(1).unwrap().to_string(),
            );
            continue;
        }
        // handle head part
        match index {
            0 => associative.insert("month", value.to_string()),
            1 => associative.insert("day", value.to_string()),
            2 => associative.insert("time", value.to_string()),
            3 => associative.insert("hostname", value.to_string()),
            5 => {
                // length only 1 mean: string only content "["
                // so need to get next element
                if value.len() == 1 {
                    associative.insert("uptime", remove_brackets(split_log.get(6).unwrap()))
                } else {
                    associative.insert("uptime", remove_brackets(value))
                }
            }
            7 => {
                // if value contain "UFW", the next element is the event data
                if value.contains("[UFW") {
                    let index8 = split_log.get(8).unwrap();
                    // if this value contain "]", that is all event name
                    // else, concat this and next element
                    if index8.contains("]") {
                        associative.insert("event", remove_brackets(index8))
                    } else {
                        associative.insert(
                            "event",
                            format!("{} {}", index8, remove_brackets(split_log.get(9).unwrap())),
                        )
                    }
                } else {
                    associative.insert("event", remove_brackets(value))
                }
            }
            _ => None,
        };
        // handle flag
        match value.trim() {
            "SYN" => associative.insert("syn", "1".to_string()),
            "ACK" => associative.insert("ack", "1".to_string()),
            "FIN" => associative.insert("fin", "1".to_string()),
            "RST" => associative.insert("rst", "1".to_string()),
            "PSH" => associative.insert("psh", "1".to_string()),
            "CWR" => associative.insert("cwr", "1".to_string()),
            "ECE" => associative.insert("ece", "1".to_string()),
            "DF" => associative.insert("df", "1".to_string()),
            _ => None,
        };
    }

    associative
}

/// Replace brackets `[`, `]` in string
fn remove_brackets(string: &str) -> String {
    string.replace("[", "").replace("]", "")
}

/// Get vector of UfwLog object from log file
pub fn get_ufwlog_vec(path: &str) -> Vec<UfwLog> {
    let log_by_line = read_lines(path);

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
    let ufw_log_vec: Vec<UfwLog> = log_by_line
        .iter()
        .map(|log| UfwLog::new(to_hashmap(log)))
        .collect();
    pb.finish_with_message("Parsed!");
    ufw_log_vec
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    // test split by space
    fn test_split() {
        let some_log: String = String::from("Apr 11 20:28:26");
        assert_eq!(split_by_space(&some_log), vec!["Apr", "11", "20:28:26"]);
    }

    #[test]
    // test split by space and should filter empty element
    fn test_split_has_empty_string() {
        let some_log: String = String::from("Apr  7 20:28:26");
        assert_eq!(split_by_space(&some_log), vec!["Apr", "7", "20:28:26"]);
    }

    #[test]
    // test split by space and should filter empty element
    fn test_remove_brackets() {
        let string: &str = "[UFW LOG]";
        assert_eq!(remove_brackets(string), String::from("UFW LOG"));
    }
}
