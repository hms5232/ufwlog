use crate::error::Error;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::io;
use std::path::Path;
use std::str::FromStr;

/// An ufw log entry
///
/// Each log record will be parsed into a `UfwLog` struct.
///
/// If the field may not exist in some log level, it will be declared as `Option` type.
///
/// Each field mean can see the following site:
/// * <https://help.ubuntu.com/community/UFW#Interpreting_Log_Entries>
/// * <https://unix.stackexchange.com/a/702909>
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
    ///
    /// See [`Policy`] for possible values.
    pub policy: Policy,

    /// The network interface the packet arrived on (e.g. `eth0`).
    ///
    /// Empty string if this is not an incoming event.
    pub r#in: String,
    /// The network interface the packet departed from (e.g. `eth0`).
    ///
    /// Empty string if this is not an outgoing event.
    pub out: String,
    /// A 14-byte combination of destination MAC, source MAC, and EtherType fields.
    ///
    /// Follows the order found in the Ethernet II header.
    pub mac: String,
    /// source IP
    pub src: String,
    /// destination IP
    pub dst: String,
    /// length of packet
    pub len: u32,
    /// Type of Service.
    ///
    /// An Internet Protocol field which indicates the type of service for this internet fragment.
    pub tos: Option<String>,
    /// Precedence field in the IP header.
    ///
    /// Indicates the priority of the packet.
    pub prec: Option<String>,
    /// time to live
    pub ttl: Option<u16>,
    /// IP packet identifier.
    ///
    /// Used to identify fragments of the same original packet during reassembly.
    pub id: Option<u32>,
    /// don't fragment
    ///
    /// Set in the IP header.
    ///
    /// When `true`, the packet must not be fragmented; it will be dropped if it
    /// exceeds the MTU of the next hop.
    pub df: bool,
    /// Network protocol (e.g. `TCP`, `UDP`, `ICMP`).
    pub proto: String,
    /// source port
    ///
    /// Only present for protocols that use ports, such as TCP and UDP.
    pub spt: Option<u16>,
    /// detestation port
    ///
    /// Only present for protocols that use ports, such as TCP and UDP.
    pub dpt: Option<u16>,
    /// TCP receive window size in bytes.
    ///
    /// Indicates the amount of data the sender is willing to receive before
    /// requiring an acknowledgment.
    pub window: Option<u32>,
    /// Reserved bits in the TCP header.
    ///
    /// Should always be zero; non-zero values may indicate malformed packets.
    pub res: String,

    // TCP control bits / flag
    // Order by TCP flag order: [RFC 793](https://datatracker.ietf.org/doc/html/rfc793).
    /// Congestion Window Reduced
    ///
    /// A Congestion Window Reduced (CWR) flag in the TCP header so that the data sender can inform
    /// the data receiver that the congestion window has been reduced.
    ///
    /// Introduced in [RFC 3168](https://datatracker.ietf.org/doc/html/rfc3168).
    pub cwr: bool,
    /// ECN-Echo
    ///
    /// An ECN-Echo (ECE) flag in the TCP header so that the data receiver can inform the data
    /// sender when a CE packet has been received
    ///
    /// Introduced in [RFC 3168](https://datatracker.ietf.org/doc/html/rfc3168).
    pub ece: bool,
    /// Urgent Pointer
    ///
    /// A control bit (urgent), occupying no sequence space, used to
    /// indicate that the receiving user should be notified to do
    /// urgent processing as long as there is data to be consumed with
    /// sequence numbers less than the value indicated in the urgent
    /// pointer.
    ///
    /// Introduced in [RFC 793](https://datatracker.ietf.org/doc/html/rfc793).
    pub urg: bool,
    /// acknowledgment
    ///
    /// A control bit (acknowledge) occupying no sequence space, which
    /// indicates that the acknowledgment field of this segment
    /// specifies the next sequence number the sender of this segment
    /// is expecting to receive, hence acknowledging receipt of all
    /// previous sequence numbers.
    ///
    /// Introduced in [RFC 793](https://datatracker.ietf.org/doc/html/rfc793).
    pub ack: bool,
    /// Push Function.
    ///
    /// A control bit occupying no sequence space, indicating that
    /// this segment contains data that must be pushed through to the
    /// receiving user.
    ///
    /// Introduced in [RFC 793](https://datatracker.ietf.org/doc/html/rfc793).
    pub psh: bool,
    /// Reset the connection.
    ///
    /// A control bit (reset), occupying no sequence space, indicating
    /// that the receiver should delete the connection without further
    /// interaction. The receiver can determine, based on the
    /// sequence number and acknowledgment fields of the incoming
    /// segment, whether it should honor the reset command or ignore
    /// it. In no case does receipt of a segment containing RST give
    /// rise to an RST in response.
    ///
    /// Introduced in [RFC 793](https://datatracker.ietf.org/doc/html/rfc793).
    pub rst: bool,
    /// Synchronize sequence numbers.
    ///
    /// A control bit in the incoming segment, occupying one sequence
    /// number, used at the initiation of a connection, to indicate
    /// where the sequence numbering will start.
    ///
    /// Introduced in [RFC 793](https://datatracker.ietf.org/doc/html/rfc793).
    pub syn: bool,
    /// No more data from sender.
    ///
    /// A control bit (finis) occupying one sequence number, which
    /// indicates that the sender will send no more data or control
    /// occupying sequence space.
    ///
    /// Introduced in [RFC 793](https://datatracker.ietf.org/doc/html/rfc793).
    pub fin: bool,

    // control bit / flag related
    /// TCP urgent pointer.
    ///
    /// This field communicates the current value of the urgent pointer as a
    /// positive offset from the sequence number in this segment. The
    /// urgent pointer points to the sequence number of the octet following
    /// the urgent data. This field is only be interpreted in segments with
    /// the URG control bit set.
    ///
    /// Introduced in [RFC 793](https://datatracker.ietf.org/doc/html/rfc793).
    pub urgp: Option<u16>,

    /// Traffic class (IPv6 only).
    ///
    /// Similar to the TOS field in IPv4, used to mark packet priority and service type.
    /// Expected range: 0–255, but the exact type is unconfirmed.
    pub tc: Option<u8>,
    /// hop limit
    pub hoplimit: Option<u8>,
    /// Flow label (IPv6 only).
    ///
    /// Identifies packets belonging to the same flow, allowing routers to process
    // /// them consistently. Expected range: 0–1048575 (20-bit value)
    pub flowlbl: Option<u32>,
    /// ICMP/ICMPv6 message type.
    ///
    /// Indicates the kind of ICMP message (e.g. `8` = Echo Request, `0` = Echo Reply).
    pub r#type: Option<u8>,
    /// ICMP/ICMPv6 sub-code for the message type.
    ///
    /// Provides additional context for the `type` field.
    pub code: Option<u8>,
    /// ICMP sequence number.
    ///
    /// Used to match ICMP request and reply pairs, and to detect packet loss or reordering.
    pub seq: Option<u32>,
    /// Maximum Transmission Unit.
    ///
    /// The largest packet size (in bytes) that the network interface can transmit.
    /// Appears in ICMP "Packet Too Big" messages. Common value: 1500 (Ethernet).
    pub mtu: Option<u16>,
    /// Netfilter packet mark.
    ///
    /// Set by iptables/nftables rules to classify or track packets.
    /// Typically represented as a hexadecimal value. Expected type is `u32`
    pub mark: Option<u32>,
    /// Physical input interface.
    ///
    /// The actual physical network interface that received the packet.
    /// May differ from [`in`](Self::in) when virtual interfaces such as bridges are involved.
    pub physin: Option<String>,
    /// Physical output interface.
    ///
    /// The actual physical network interface that sent the packet.
    /// May differ from [`out`](Self::out) when virtual interfaces such as bridges are involved.
    pub phyout: Option<String>,

    /// origin content of log
    origin: String,
}

impl UfwLog {
    /// Initial a UfwLog with default value
    fn new() -> Self {
        Self {
            month: 0,
            day: 0,
            time: "".to_string(),
            hostname: "".to_string(),
            uptime: "".to_string(),
            policy: Policy::default(),
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
            cwr: false,
            ece: false,
            urg: false,
            ack: false,
            psh: false,
            rst: false,
            syn: false,
            fin: false,
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
            origin: "".to_string(),
        }
    }

    /// fill data with given data.
    /// If the data is empty, return a new UfwLog object with default value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::collections::HashMap;
    /// use ufwlog::UfwLog;
    ///
    /// let mut hashmap: HashMap<&str, String> = HashMap::new();
    /// hashmap.insert("month", String::from("Jan"));
    /// hashmap.insert("day", String::from("1"));
    ///
    /// let log: UfwLog = UfwLog::from_hashmap(hashmap).unwrap();
    ///
    /// // filled data
    /// assert_eq!(log.month, 1);
    /// assert_eq!(log.day, 1);
    /// // not given so default value
    /// assert_eq!(log.time, "");
    /// assert_eq!(log.get_origin(), "");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the data is invalid.
    ///
    /// ```rust
    /// use std::collections::HashMap;
    /// use ufwlog::UfwLog;
    ///
    /// let mut hashmap: HashMap<&str, String> = HashMap::new();
    /// hashmap.insert("day", String::from("365"));
    ///
    /// let result = UfwLog::from_hashmap(hashmap);
    /// assert!(result.is_err());
    /// ```
    pub fn from_hashmap(data: HashMap<&str, String>) -> Result<Self, Error> {
        // new a UfwLog object with default value
        let mut new = Self::new();

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
                "event" => new.policy = Policy::from(value),
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
                "urg" => new.urg = value == "1",
                "urgp" => {
                    new.urgp =
                        Some(
                            value
                                .parse::<u16>()
                                .map_err(|_| ParseError::InvalidNumber {
                                    field: "urgp",
                                    value,
                                })?,
                        )
                }
                "tc" => {
                    new.tc = Some(
                        value
                            .parse::<u8>()
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
                                .parse::<u32>()
                                .map_err(|_| ParseError::InvalidNumber {
                                    field: "flowlbl",
                                    value,
                                })?,
                        )
                }
                "type" => {
                    new.r#type =
                        Some(value.parse::<u8>().map_err(|_| ParseError::InvalidNumber {
                            field: "type",
                            value,
                        })?)
                }
                "code" => {
                    new.code = Some(value.parse::<u8>().map_err(|_| ParseError::InvalidNumber {
                        field: "code",
                        value,
                    })?)
                }
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
                "mark" => {
                    new.mark =
                        Some(
                            value
                                .parse::<u32>()
                                .map_err(|_| ParseError::InvalidNumber {
                                    field: "mark",
                                    value,
                                })?,
                        )
                }
                "physin" => new.physin = Some(value),
                "phyout" => new.phyout = Some(value),
                _ => (),
            }
        }
        Ok(new)
    }

    /// Read log file and get vector of UfwLog
    ///
    /// This function reads the **entire file** and returns a vector of UfwLog objects. If your log file
    /// is very large or RAM is limited, you may want to use [Self::from_buf_reader] instead.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to log file
    ///
    /// # Errors
    ///
    /// Returns an error if the log file cannot be read or parsed.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Vec<UfwLog>, Error> {
        crate::parser::get_ufwlog_vec(path)
    }

    /// Get an iterator of UfwLog from a buffer reader.
    ///
    /// This function reads the log file line by line and returns an iterator of UfwLog objects or errors.
    ///
    /// That will be more memory efficient than [Self::from_file] when the log file is very large,
    /// or useful when the source is not a file, such as stdin or a network stream.
    ///
    /// # Errors
    ///
    /// Returns an iterator that contains error if the line cannot be read or parsed, or the io is invalid.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::io::BufReader;
    /// use ufwlog::UfwLog;
    /// use ufwlog::error::Error;
    ///
    /// fn main() {
    ///     // simulate log stream or stdin, there are two lines, each line is a log record
    ///     let log_str = "Jan 16 02:13:52 103213020 kernel: [3601090.569259] [UFW AUDIT] IN= OUT=lo SRC=127.0.0.1 DST=127.0.0.1 LEN=84 TOS=0x00 PREC=0x00 TTL=64 ID=33539 DF PROTO=ICMP TYPE=8 CODE=0 ID=10289 SEQ=1";
    ///     let log_str2 = "Apr 22 09:21:07 7C56 kernel: [ 3353.096838] [UFW BLOCK] IN=enp42s0 OUT= MAC= SRC=192.168.1.147 DST=230.230.230.230 LEN=160 TOS=0x00 PREC=0x00 TTL=1 ID=54530 DF PROTO=UDP SPT=60948 DPT=8978 LEN=140";
    ///     let logs_str = [log_str, log_str2]; // used for assert
    ///     // simulating log stream or stdin, add a newline between logs
    ///     let stdin = format!("{}\n{}", log_str, log_str2);
    ///     // new a buffer reader
    ///     let buf_reader = BufReader::new(stdin.as_bytes());
    ///     // call from_buf_reader(), then get an iterator containing UfwLog objects or errors
    ///     let ufwlog_iter = UfwLog::from_buf_reader(buf_reader);
    ///     // iterate over the iterator
    ///     for (line_number, ufwlog) in ufwlog_iter.enumerate() {
    ///         assert!(ufwlog.is_ok());
    ///         assert_eq!(*logs_str.get(line_number).unwrap(), ufwlog.unwrap().get_origin());
    ///     }
    /// }
    /// ```
    pub fn from_buf_reader(
        buf_reader: impl io::BufRead,
    ) -> impl Iterator<Item = Result<UfwLog, Error>> {
        buf_reader.lines().map(|l| {
            l.map_err(From::from)
                .and_then(|s| UfwLog::from_str(s.as_str()))
        })
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

impl FromStr for UfwLog {
    type Err = Error;

    /// Parse **single log string** and try to convert to UfwLog struct.
    ///
    /// # Errors
    ///
    /// Returns an error if the log string cannot be parsed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::str::FromStr;
    /// use ufwlog::UfwLog;
    ///
    /// let log_str = "Jan 16 02:13:52 103213020 kernel: [3601090.569259] [UFW AUDIT] IN= OUT=lo SRC=127.0.0.1 DST=127.0.0.1 LEN=84 TOS=0x00 PREC=0x00 TTL=64 ID=33539 DF PROTO=ICMP TYPE=8 CODE=0 ID=10289 SEQ=1";
    /// let log = UfwLog::from_str(log_str).unwrap();
    /// assert_eq!(log_str, log.get_origin());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        UfwLog::from_hashmap(crate::parser::to_hashmap(s))
    }
}

/// The ufw policy list.
///
/// Community may call it "action" or "event", but we use "policy", as variable named in [source code](https://launchpad.net/ufw).
#[derive(Debug, Default, PartialEq)]
pub enum Policy {
    /// Unknown policy.
    ///
    /// If you see `Unknown` in the output, it means the policy is not recognized.
    /// Please report to [GitHub](https://github.com/hms5232/ufwlog/issues).
    #[default]
    Unknown,
    /// Packet is matched by a deny/reject rule.
    ///
    /// This is default policy to incoming packets.
    Block,
    /// Packet is matched by an allow rule.
    ///
    /// This is default policy to outgoing packets.
    Allow,
    /// Only show in medium and higher log level.
    Audit,
    /// INVALID packets (packets not associated with a known connection).
    ///
    /// Only show in medium and higher log level.
    AuditInvalid,
    /// Packet was blocked by rate limiting.
    LimitBlock,
}

impl From<String> for Policy {
    fn from(value: String) -> Self {
        match value.to_uppercase().as_str() {
            "BLOCK" => Policy::Block,
            "ALLOW" => Policy::Allow,
            "AUDIT" => Policy::Audit,
            "AUDIT INVALID" => Policy::AuditInvalid,
            "LIMIT BLOCK" => Policy::LimitBlock,
            _ => Policy::Unknown,
        }
    }
}

impl Display for Policy {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Policy::Block => "BLOCK",
                Policy::Allow => "ALLOW",
                Policy::Audit => "AUDIT",
                Policy::AuditInvalid => "AUDIT INVALID",
                Policy::LimitBlock => "LIMIT BLOCK",
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
