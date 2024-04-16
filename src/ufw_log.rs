use std::collections::HashMap;

/// An ufw log
///
/// Each field mean can see the following site:
/// https://help.ubuntu.com/community/UFW#Interpreting_Log_Entries
/// https://unix.stackexchange.com/a/702909
#[derive(Debug)]
pub struct UfwLog {
    origin: String,

    month: u8,
    day: u8,
    time: String,
    hostname: String,
    uptime: String,
    action: String,

    r#in: Option<String>,
    out: Option<String>,
    mac: Option<String>,
    src: String,
    dst: String,
    len: u32,
    tos: Option<String>, // type of service
    prec: Option<String>,
    ttl: Option<u16>,
    id: Option<u32>,
    df: bool, // don't fragment
    proto: String,
    spt: Option<u16>,    // source port
    dpt: Option<u16>,    // detestation port
    window: Option<u32>, // the size of packet the sender is willing to receive
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

    tc: Option<i32>,      // TODO: type check need
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

impl UfwLog {
    /// Initial a UfwLog with default value
    /// or fill data with given data.
    pub fn new(data: HashMap<&str, String>) -> Self {
        // new a UfwLog object with default value
        let mut new = Self {
            origin: "".to_string(),
            month: 0,
            day: 0,
            time: "".to_string(),
            hostname: "".to_string(),
            uptime: "".to_string(),
            action: "".to_string(),
            r#in: None,
            out: None,
            mac: None,
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
            urgp: false,
            tc: None,
            hoplimit: None,
            flowbl: None,
            r#type: None,
            code: None,
            seq: None,
            mtu: None,
            mark: None,
            physin: None,
            phyout: None,
        };

        if data.is_empty() {
            return new;
        }

        // fill data
        for (key, value) in data {
            let lowercase_key = key.to_lowercase();
            match lowercase_key.as_str() {
                "origin" => new.origin = value,
                "month" => new.month = get_month_number(value),
                "time" => new.time = value,
                "hostname" => new.hostname = value,
                "uptime" => new.uptime = value,
                "action" => new.action = value,
                "in" => new.r#in = Some(value),
                "out" => new.out = Some(value),
                "mac" => new.mac = Some(value),
                "src" => new.src = value,
                "dst" => new.dst = value,
                "len" => new.len = value.parse::<u32>().unwrap(),
                "tos" => new.tos = Some(value),
                "prec" => new.prec = Some(value),
                "ttl" => new.ttl = Some(value.parse::<u16>().unwrap()),
                "id" => new.id = Some(value.parse::<u32>().unwrap()),
                "df" => new.df = if value == "1" { true } else { false },
                "proto" => new.proto = value,
                "spt" => new.spt = Some(value.parse::<u16>().unwrap()),
                "dpt" => new.dpt = Some(value.parse::<u16>().unwrap()),
                "window" => new.window = Some(value.parse::<u32>().unwrap()),
                "res" => new.res = value,
                "syn" => new.syn = if value == "1" { true } else { false },
                "ack" => new.ack = if value == "1" { true } else { false },
                "fin" => new.fin = if value == "1" { true } else { false },
                "rst" => new.rst = if value == "1" { true } else { false },
                "psh" => new.psh = if value == "1" { true } else { false },
                "cwr" => new.cwr = if value == "1" { true } else { false },
                "ece" => new.ece = if value == "1" { true } else { false },
                "urgp" => new.urgp = if value == "1" { true } else { false },
                "tc" => new.tc = Some(value.parse::<i32>().unwrap()),
                "hoplimit" => new.hoplimit = Some(value.parse::<u8>().unwrap()),
                "flowbl" => new.flowbl = Some(value.parse::<i32>().unwrap()),
                "r#type" => new.r#type = Some(value.parse::<i32>().unwrap()),
                "code" => new.code = Some(value),
                "seq" => new.seq = Some(value.parse::<u32>().unwrap()),
                "mtu" => new.mtu = Some(value.parse::<u16>().unwrap()),
                "mark" => new.mark = Some(value),
                "physin" => new.physin = Some(value),
                "phyout" => new.phyout = Some(value),
                _ => (),
            }
        }
        new
    }
}

/// The ufw action list
enum UfwAction {
    Black,
    Allow,
    Deny,
    Audit,
    AuditInvalid, // AUDIT INVALID
}

const MONTH: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Get the month number
///
/// # Example
///
/// ```
/// assert_eq!(get_month_number("Apr".to_string(), 4))
/// ```
fn get_month_number(string: String) -> u8 {
    (MONTH.iter().position(|&r| r == string.trim()).unwrap() as u8) + 1
}
