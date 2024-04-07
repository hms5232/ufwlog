//! A parser for ufw log file.

use std::fs;

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
