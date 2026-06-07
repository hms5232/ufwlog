use crate::error::Error;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};

/// An ufw log
///
/// If the field may not exist in some log level, it will be declared as `Option` type.
///
/// Each field mean can see the following site:
/// * https://help.ubuntu.com/community/UFW#Interpreting_Log_Entries
/// * https://unix.stackexchange.com/a/702909
#[derive(Debug)]
pub struct UfwLog {
    /// month of log record, 1-12
    pub month: u8,
    /// day of log record, 1-31
    pub day: u8,
    /// time of log record, format: "HH:MM:SS"
    pub time: String,
    /// The server's hostname
    pub hostname: String,
    /// The time in seconds since boot.
    pub uptime: String,
    /// Short description of logged event
    pub event: LoggedEvent,

    /// If set, then the event was an incoming event.
    pub r#in: String,
    /// If set, then the event was an outgoing event.
    pub out: String,
    /// a 14-byte combination of the Destination MAC, Source MAC, and EtherType fields, following the order found in the Ethernet II header.
    pub mac: String,
    /// source IP
    pub src: String,
    /// destination IP
    pub dst: String,
    /// length of packet
    pub len: u32,
    /// type of service
    pub tos: Option<String>,
    pub prec: Option<String>,
    /// time to live
    pub ttl: Option<u16>,
    pub id: Option<u32>,
    /// don't fragment
    pub df: bool,
    /// protocol
    pub proto: String,
    /// source port
    pub spt: Option<u16>,
    /// detestation port
    pub dpt: Option<u16>,
    /// the size of packet the sender is willing to receive
    pub window: Option<u32>,
    pub res: String,

    // TCP control bits / flag
    /// synchronization
    pub syn: bool,
    /// acknowledgment
    pub ack: bool,
    /// last package from sender
    pub fin: bool,
    /// Reset the connection
    pub rst: bool,
    /// push function
    pub psh: bool,
    /// Congestion window reduced
    pub cwr: bool,
    /// ECN-Echo
    pub ece: bool,
    /// Indicates whether the urgent pointer field is significant.
    ///
    /// 0 means it's not.
    pub urgp: Option<bool>,

    pub tc: Option<i32>, // TODO: type check need
    /// hop limit
    pub hoplimit: Option<u8>,
    /// flow label
    pub flowlbl: Option<i32>, // TODO: type need check
    pub r#type: Option<i32>,  // TODO: type need check
    pub code: Option<String>, // TODO: type check need
    pub seq: Option<u32>,
    pub mtu: Option<u16>,
    pub mark: Option<String>, // TODO: type check need

    // unconfirmed
    pub physin: Option<String>,
    pub phyout: Option<String>,

    /// origin content of log
    origin: String,
}

impl UfwLog {
    /// Initial a UfwLog with default value
    /// or fill data with given data.
    pub fn new(data: HashMap<&str, String>) -> Result<Self, Error> {
        // new a UfwLog object with default value
        let mut new = Self {
            origin: "".to_string(),
            month: 0,
            day: 0,
            time: "".to_string(),
            hostname: "".to_string(),
            uptime: "".to_string(),
            event: LoggedEvent::default(),
            r#in: "".to_string(),
            out: "".to_string(),
            mac: "".to_string(),
            src: "".to_string(),
            dst: "".to_string(),
            len: 0,
            tos: None,
            prec: None,
            ttl: None,
            id: None,
            df: false,
            proto: "".to_string(),
            spt: None,
            dpt: None,
            window: None,
            res: "".to_string(),
            syn: false,
            ack: false,
            fin: false,
            rst: false,
            psh: false,
            cwr: false,
            ece: false,
            urgp: None,
            tc: None,
            hoplimit: None,
            flowlbl: None,
            r#type: None,
            code: None,
            seq: None,
            mtu: None,
            mark: None,
            physin: None,
            phyout: None,
        };

        if data.is_empty() {
            return Ok(new);
        }

        // fill data
        for (key, value) in data {
            let lowercase_key = key.to_lowercase();
            match lowercase_key.as_str() {
                "origin" => new.origin = value,
                "month" => new.month = get_month_number(value),
                "day" => {
                    new.day = value.parse::<u8>().map_err(|_| ParseError::InvalidNumber {
                        field: "day",
                        value,
                    })?
                }
                "time" => new.time = value,
                "hostname" => new.hostname = value,
                "uptime" => new.uptime = value,
                "event" => new.event = LoggedEvent::from(value),
                "in" => new.r#in = value,
                "out" => new.out = value,
                "mac" => new.mac = value,
                "src" => new.src = value,
                "dst" => new.dst = value,
                "len" => {
                    new.len = value
                        .parse::<u32>()
                        .map_err(|_| ParseError::InvalidNumber {
                            field: "len",
                            value,
                        })?
                }
                "tos" => new.tos = Some(value),
                "prec" => new.prec = Some(value),
                "ttl" => {
                    new.ttl = Some(
                        value
                            .parse::<u16>()
                            .map_err(|_| ParseError::InvalidNumber {
                                field: "ttl",
                                value,
                            })?,
                    )
                }
                "id" => {
                    new.id = Some(
                        value
                            .parse::<u32>()
                            .map_err(|_| ParseError::InvalidNumber { field: "id", value })?,
                    )
                }
                "df" => new.df = value == "1",
                "proto" => new.proto = value,
                "spt" => {
                    new.spt = Some(
                        value
                            .parse::<u16>()
                            .map_err(|_| ParseError::InvalidNumber {
                                field: "spt",
                                value,
                            })?,
                    )
                }
                "dpt" => {
                    new.dpt = Some(
                        value
                            .parse::<u16>()
                            .map_err(|_| ParseError::InvalidNumber {
                                field: "dpt",
                                value,
                            })?,
                    )
                }
                "window" => {
                    new.window =
                        Some(
                            value
                                .parse::<u32>()
                                .map_err(|_| ParseError::InvalidNumber {
                                    field: "window",
                                    value,
                                })?,
                        )
                }
                "res" => new.res = value,
                "syn" => new.syn = value == "1",
                "ack" => new.ack = value == "1",
                "fin" => new.fin = value == "1",
                "rst" => new.rst = value == "1",
                "psh" => new.psh = value == "1",
                "cwr" => new.cwr = value == "1",
                "ece" => new.ece = value == "1",
                "urgp" => new.urgp = Some(value == "1"),
                "tc" => {
                    new.tc = Some(
                        value
                            .parse::<i32>()
                            .map_err(|_| ParseError::InvalidNumber { field: "tc", value })?,
                    )
                }
                "hoplimit" => {
                    new.hoplimit =
                        Some(value.parse::<u8>().map_err(|_| ParseError::InvalidNumber {
                            field: "hoplimit",
                            value,
                        })?)
                }
                "flowlbl" => {
                    new.flowlbl =
                        Some(
                            value
                                .parse::<i32>()
                                .map_err(|_| ParseError::InvalidNumber {
                                    field: "flowlbl",
                                    value,
                                })?,
                        )
                }
                "type" => {
                    new.r#type =
                        Some(
                            value
                                .parse::<i32>()
                                .map_err(|_| ParseError::InvalidNumber {
                                    field: "type",
                                    value,
                                })?,
                        )
                }
                "code" => new.code = Some(value),
                "seq" => {
                    new.seq = Some(
                        value
                            .parse::<u32>()
                            .map_err(|_| ParseError::InvalidNumber {
                                field: "seq",
                                value,
                            })?,
                    )
                }
                "mtu" => {
                    new.mtu = Some(
                        value
                            .parse::<u16>()
                            .map_err(|_| ParseError::InvalidNumber {
                                field: "mtu",
                                value,
                            })?,
                    )
                }
                "mark" => new.mark = Some(value),
                "physin" => new.physin = Some(value),
                "phyout" => new.phyout = Some(value),
                _ => (),
            }
        }
        Ok(new)
    }

    /// Read log file and get vector of UfwLog
    ///
    /// # Arguments
    ///
    /// * `path` - Path to log file
    ///
    /// # Errors
    ///
    /// Returns an error if the log file cannot be read or parsed.
    pub fn from_file(path: &str) -> Result<Vec<UfwLog>, Error> {
        crate::parser::get_ufwlog_vec(path)
    }

    /// Get origin content of log
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::str::FromStr;
    /// use ufwlog::UfwLog;
    ///
    /// // original log content
    /// let log_str = "Jan 16 02:13:52 103213020 kernel: [3601090.569259] [UFW AUDIT] IN= OUT=lo SRC=127.0.0.1 DST=127.0.0.1 LEN=84 TOS=0x00 PREC=0x00 TTL=64 ID=33539 DF PROTO=ICMP TYPE=8 CODE=0 ID=10289 SEQ=1";
    ///
    /// // make an UfwLog struct
    /// let log: UfwLog = UfwLog::from_str(log_str).unwrap();
    ///
    /// // By calling the get_origin method, it will return the original log content
    /// assert_eq!(log_str, log.get_origin())
    /// ```
    pub fn get_origin(&self) -> &str {
        &self.origin
    }
}

impl std::str::FromStr for UfwLog {
    type Err = Error;

    /// Parse log string and try to convert to UfwLog struct
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        UfwLog::new(crate::parser::to_hashmap(s))
    }
}

/// The ufw logged event list
#[derive(Debug, Default, PartialEq)]
pub enum LoggedEvent {
    #[default]
    Unknown, // default
    Block,
    Allow,
    Deny,
    Audit,
    AuditInvalid, // AUDIT INVALID
}

impl From<String> for LoggedEvent {
    fn from(value: String) -> Self {
        match value.to_uppercase().as_str() {
            "BLOCK" => LoggedEvent::Block,
            "ALLOW" => LoggedEvent::Allow,
            "DENY" => LoggedEvent::Deny,
            "AUDIT" => LoggedEvent::Audit,
            "AUDIT INVALID" => LoggedEvent::AuditInvalid,
            _ => LoggedEvent::Unknown,
        }
    }
}

impl Display for LoggedEvent {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                LoggedEvent::Block => "BLOCK",
                LoggedEvent::Allow => "ALLOW",
                LoggedEvent::Deny => "DENY",
                LoggedEvent::Audit => "AUDIT",
                LoggedEvent::AuditInvalid => "AUDIT INVALID",
                _ => "UNKNOWN",
            }
        )
    }
}

const MONTH: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Convert month abbreviation to month number (1-12)
///
/// This is an internal helper function that converts three-letter
/// month abbreviations to their corresponding numeric values.
///
/// # Arguments
///
/// * `string` - A string containing the month abbreviation (e.g., "Jan", "Apr", "Dec")
///
/// # Returns
///
/// Returns a `u8` representing the month number (1-12)
///
/// Returns 0 if the input string is not a valid month abbreviation
fn get_month_number(string: String) -> u8 {
    match MONTH.iter().position(|&r| r == string.trim()) {
        Some(pos) => (pos as u8) + 1,
        None => 0,
    }
}

/// Error type for parsing log content into UfwLog
#[derive(Debug)]
pub enum ParseError {
    InvalidNumber {
        field: &'static str,
        value: String,
    },
    InvalidFormat {
        field: &'static str,
        description: String,
    },
}

impl Display for ParseError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            ParseError::InvalidNumber { field, value } => {
                write!(f, "Invalid number for field '{field}': '{value}'")
            }
            ParseError::InvalidFormat { field, description } => {
                write!(f, "Invalid format for field '{field}': {description}")
            }
        }
    }
}

impl std::error::Error for ParseError {}
