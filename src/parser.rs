//! A parser for ufw log file.

use crate::error::Error;
use crate::ufw_log::UfwLog;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::str::FromStr;

/// Read file and get content line by line
///
/// This function reads the entire file and returns each line as a string
/// in a vector. Empty lines are preserved.
///
/// # Arguments
///
/// * `path` - Path to the file to read
///
/// # Returns
///
/// Returns a `Ok(Vec<String>)` containing each line from the file
pub fn read_lines(path: impl AsRef<Path>) -> Result<Vec<String>, Error> {
    // read log file
    let file = File::open(path);
    if file.is_err() {
        return Err(Error::from(file.err().unwrap()));
    }

    BufReader::new(file?)
        .lines()
        .map(|line| line.map_err(Error::from))
        .collect::<Result<Vec<String>, Error>>()
}

/// Split log record by space, and filter empty element(s).
pub fn split_by_space(log: &str) -> Vec<&str> {
    log.split(" ").filter(|&x| !x.is_empty()).collect()
}

/// convert log record string to hashmap
pub fn to_hashmap(log: &str) -> HashMap<&str, String> {
    let split_log = split_by_space(log);
    let mut associative = HashMap::new();
    let mut square_bracket_range = false;
    let mut square_brackets_data: Vec<String> = vec![];

    // add origin record
    associative.insert("origin", log.to_owned());
    // handle each fields
    for (index, value) in split_log.iter().enumerate() {
        // handle square brackets
        if value.contains("[") {
            square_bracket_range = true;
            // if not end of square brackets content, push to data and go to next field
            if !value.contains("]") {
                square_brackets_data.push(remove_brackets(value));
                continue;
            }
            // else, it is end of square brackets content, go to next if block
        }
        if square_bracket_range {
            square_brackets_data.push(remove_brackets(value));

            // end of square brackets content
            if value.contains("]") {
                square_bracket_range = false;

                if index <= 6 {
                    associative.insert("uptime", square_brackets_data.join(" ").trim().to_string());
                } else if index <= 9 {
                    associative.insert("policy", square_brackets_data.join(" ").trim().to_string());
                } else {
                    // TODO: handle Original Data Datagram (RFC 792, 1812, 4443)
                }

                square_brackets_data = vec![]; // reset
            }

            continue;
        }

        // handle record has equal symbol
        if value.contains("=") {
            // field => value
            let (f, v) = value.split_once("=").unwrap();

            // handle duplicate fields
            if associative.contains_key(f) {
                continue;
            }

            associative.insert(f, v.to_string());
            continue;
        }
        // handle head part
        match index {
            0 => {
                associative.insert("month", value.to_string());
            }
            1 => {
                associative.insert("day", value.to_string());
            }
            2 => {
                associative.insert("time", value.to_string());
            }
            3 => {
                associative.insert("hostname", value.to_string());
            }
            _ => {}
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
            "URG" => associative.insert("urg", "1".to_string()),
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
///
/// # Arguments
///
/// * `path` - Path to log file
///
/// # Errors
///
/// Returns an error if the log file cannot be read or parsed.
pub fn get_ufwlog_vec(path: impl AsRef<Path>) -> Result<Vec<UfwLog>, Error> {
    let log_by_line = read_lines(path)?;
    // parse as UfwLog struct
    let mut ufw_log_vec: Vec<UfwLog> = vec![];
    for log in log_by_line.iter() {
        let ul = UfwLog::from_str(log)?;
        ufw_log_vec.push(ul);
    }
    Ok(ufw_log_vec)
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
