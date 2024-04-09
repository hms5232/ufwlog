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
