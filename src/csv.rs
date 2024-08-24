use std::collections::HashMap;
use std::error::Error;
use std::path::PathBuf;

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
    // resolve file path and name
    let mut path = PathBuf::from(output_filename.unwrap_or("ufwlog.csv"));
    if path.file_name().is_none() {
        return Err(Box::from("Please specify a file name."));
    }
    if path.extension().is_none() {
        path.set_extension("csv");
    };

    let mut wtr = csv::Writer::from_path(path.to_str().unwrap())?;
    wtr.write_record(HEADER)
        .expect("Write failed when try to insert header row.");

    let mut count: u32 = 0;
    for i in logs {
        count += 1;
        print!("Handle {} rows...", count);
        print!("\r");

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
        row.push(i.get("TOS").unwrap_or(&"".to_string()).to_owned());
        row.push(i.get("PREC").unwrap_or(&"".to_string()).to_owned());
        row.push(i.get("TTL").unwrap_or(&"".to_string()).to_owned());
        row.push(i.get("ID").unwrap_or(&"".to_string()).to_owned());
        row.push(if i.contains_key("df") {
            "DF".to_string()
        } else {
            "".to_string()
        });
        row.push(i.get("PROTO").unwrap().to_owned());
        row.push(i.get("SPT").unwrap_or(&"".to_string()).to_owned());
        row.push(i.get("DPT").unwrap_or(&"".to_string()).to_owned());
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
    println!(); // avoid output be overridden

    Ok(())
}
