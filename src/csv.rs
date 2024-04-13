use std::collections::HashMap;
use std::error::Error;

/// csv header
const HEADER: [&str; 35] = [
    "Month",
    "Day",
    "Time",
    "hostname",
    "uptime",
    "action",
    "IN",
    "OUT",
    "MAC",
    "SRC",
    "DST",
    "LEN",
    "TOS",
    "PREC",
    "TTL",
    "ID",
    "DF",
    "PROTO",
    "SPT",
    "DPT",
    "WINDOW",
    "RES",
    "Control Bits / flags",
    "URGP",
    "TC",
    "HOPLIMIT",
    "FLOWLBL",
    "TYPE",
    "CODE",
    "SEQ",
    "MTU",
    "MARK",
    "PHYSIN",
    "PHYOUT",
    "origin",
];

pub fn convert(
    logs: Vec<HashMap<&str, String>>,
    output_filename: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let file_path = output_filename.unwrap_or("./ufwlog.csv");
    let mut wtr = csv::Writer::from_path(file_path)?;
    wtr.write_record(HEADER).expect("Write failed when try to insert header row.");

    for i in logs {
        let mut row = vec![];

        // control bits / flags
        let mut flags = vec![];
        if i.contains_key("syn") {
            flags.push("SYN")
        }
        if i.contains_key("ack") {
            flags.push("ACK")
        }
        if i.contains_key("fin") {
            flags.push("FIN")
        }
        if i.contains_key("rst") {
            flags.push("RST")
        }
        if i.contains_key("psh") {
            flags.push("PSH")
        }
        if i.contains_key("cwr") {
            flags.push("CWR")
        }

        // should push by "HEADER" order
        row.push(i.get("month").unwrap().to_owned());
        row.push(i.get("day").unwrap().to_owned());
        row.push(i.get("time").unwrap().to_owned());
        row.push(i.get("hostname").unwrap().to_owned());
        row.push(i.get("uptime").unwrap().to_owned());
        row.push(i.get("action").unwrap().to_owned());
        row.push(i.get("IN").unwrap_or(&"".to_string()).to_owned());
        row.push(i.get("OUT").unwrap_or(&"".to_string()).to_owned());
        row.push(i.get("MAC").unwrap_or(&"".to_string()).to_owned());
        row.push(i.get("SRC").unwrap().to_owned());
        row.push(i.get("DST").unwrap().to_owned());
        row.push(i.get("LEN").unwrap().to_owned());
        row.push(i.get("TOS").unwrap().to_owned());
        row.push(i.get("PREC").unwrap().to_owned());
        row.push(i.get("TTL").unwrap().to_owned());
        row.push(i.get("ID").unwrap().to_owned());
        row.push(if i.contains_key("df") {
            "DF".to_string()
        } else {
            "".to_string()
        });
        row.push(i.get("PROTO").unwrap().to_owned());
        row.push(i.get("SPT").unwrap().to_owned());
        row.push(i.get("DPT").unwrap().to_owned());
        row.push(i.get("WINDOW").unwrap_or(&"".to_string()).to_owned());
        row.push(i.get("RES").unwrap_or(&"".to_string()).to_owned());
        row.push(flags.join(" "));
        row.push(i.get("URGP").unwrap_or(&"".to_string()).to_owned());
        row.push(i.get("TC").unwrap_or(&"".to_string()).to_owned());
        row.push(i.get("HOPLIMIT").unwrap_or(&"".to_string()).to_owned());
        row.push(i.get("FLOWLBL").unwrap_or(&"".to_string()).to_owned());
        row.push(i.get("TYPE").unwrap_or(&"".to_string()).to_owned());
        row.push(i.get("CODE").unwrap_or(&"".to_string()).to_owned());
        row.push(i.get("SEQ").unwrap_or(&"".to_string()).to_owned());
        row.push(i.get("MTU").unwrap_or(&"".to_string()).to_owned());
        row.push(i.get("MARK").unwrap_or(&"".to_string()).to_owned());
        row.push(i.get("PHYSIN").unwrap_or(&"".to_string()).to_owned());
        row.push(i.get("PHYOUT").unwrap_or(&"".to_string()).to_owned());
        row.push(i.get("origin").unwrap().to_owned());

        wtr.write_record(row).expect("Write csv file occur error");
    }

    Ok(())
}
