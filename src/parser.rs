//! A parser for ufw log file.

use std::collections::HashMap;
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
                key_and_value.get(1).unwrap().to_string()
            );
            continue;
        }
        // handle head part
        match index {
            0 => associative.insert("month", value.to_string()),
            1 => associative.insert("day", value.to_string()),
            2 => associative.insert("time", value.to_string()),
            3 => associative.insert("hostname", value.to_string()),
            5 => associative.insert("uptime", remove_brackets(value.to_string())),
            7 => associative.insert("action", remove_brackets(value.to_string())),
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
            _ => None,
        };
    }

    associative
}

/// Replace brackets `[`, `]` in string
fn remove_brackets(string: String) -> String {
    string.replace("[", "").replace("]", "")
}

/// An ufw log
///
/// Each field mean can see the following site:
/// https://help.ubuntu.com/community/UFW#Interpreting_Log_Entries
/// https://unix.stackexchange.com/a/702909
struct UfwLog {
    origin: String,

    month: u8,
    day: u8,
    time: String,
    hostname: String,
    uptime: String,
    action: UfwAction,

    r#in: Option<String>,
    out: Option<String>,
    mac: Option<String>,
    src: String,
    dst: String,
    len: u32,
    tos: String, // type of service
    prec: String,
    ttl: u16,
    id: u32,
    df: bool, // don't fragment
    proto: String,
    spt: u16,    // source port
    dpt: u16,    // detestation port
    window: u32, // the size of packet the sender is willing to receive
    res: String,

    // control bits / flag
    syn: bool,
    ack: bool,
    fin: bool,
    rst: bool,
    psh: bool,
    cwr: bool,
    ece: bool,
    urgp: bool,

    tc: bool,
    hoplimit: Option<u8>, // hop limit
    flowbl: Option<i32>,  // TODO: type need check
    r#type: Option<i32>,  // TODO: type need check
    code: Option<String>, // TODO: type check need
    seq: Option<u32>,
    mtu: Option<u16>,
    mark: Option<String>, // TODO: type check need

    // unconfirmed
    physin: Option<String>,
    phyout: Option<String>,
}

/// The ufw action list
enum UfwAction {
    Black,
    Allow,
    Deny,
    Audit,
    AuditInvalid, // AUDIT INVALID
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
        let string: String = String::from("[UFW LOG]");
        assert_eq!(remove_brackets(string), String::from("UFW LOG"));
    }
}
