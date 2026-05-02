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
    pub origin: String,

    pub month: u8,
    pub day: u8,
    pub time: String,
    pub hostname: String,
    pub uptime: String,
    pub event: LoggedEvent,

    pub r#in: String,
    pub out: String,
    pub mac: String,
    pub src: String,
    pub dst: String,
    pub len: u32,
    pub tos: Option<String>, // type of service
    pub prec: Option<String>,
    pub ttl: Option<u16>,
    pub id: Option<u32>,
    pub df: bool, // don't fragment
    pub proto: String,
    pub spt: Option<u16>,    // source port
    pub dpt: Option<u16>,    // detestation port
    pub window: Option<u32>, // the size of packet the sender is willing to receive
    pub res: String,

    // control bits / flag
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub cwr: bool,
    pub ece: bool,
    pub urgp: Option<bool>, // Indicates whether the urgent pointer field is relevant. 0 means it's not. Therefore, we convert it to Option<bool>.

    pub tc: Option<i32>,      // TODO: type check need
    pub hoplimit: Option<u8>, // hop limit
    pub flowlbl: Option<i32>, // TODO: type need check
    pub r#type: Option<i32>,  // TODO: type need check
    pub code: Option<String>, // TODO: type check need
    pub seq: Option<u32>,
    pub mtu: Option<u16>,
    pub mark: Option<String>, // TODO: type check need

    // unconfirmed
    pub physin: Option<String>,
    pub phyout: Option<String>,
}

impl UfwLog {
    /// Initial a UfwLog with default value
    /// or fill data with given data.
    pub fn new(data: HashMap<&str, String>) -> Result<Self, ParseError> {
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
                "urgp" => {
                    new.urgp = if value == "1" {
                        Some(true)
                    } else {
                        Some(false)
                    }
                }
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
}

impl std::str::FromStr for UfwLog {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hashmap = crate::parser::to_hashmap(s);
        UfwLog::new(hashmap)
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
