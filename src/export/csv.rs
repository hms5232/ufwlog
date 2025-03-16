use crate::export::Config;
use crate::ufw_log::UfwLog;
use indicatif::ProgressBar;
use std::error::Error;
use std::path::PathBuf;

/// csv header
const HEADER: [&str; 35] = [
    "Month",
    "Day",
    "Time",
    "hostname",
    "uptime",
    "event",
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

pub fn convert(logs: Vec<UfwLog>, config: Config) -> Result<(), Box<dyn Error>> {
    // resolve file path and name
    let mut path = PathBuf::from(config.output_filename);
    if path.file_name().is_none() {
        return Err("Please specify a file name.".into());
    }
    if path.extension().is_none() {
        path.set_extension(super::Format::Csv.get_extension());
    };
    // if the file exists, return error
    if path.exists() && !config.overwrite {
        return Err(format!(
            "The file {} is exist. Overwrite it with `--overwrite` flag.",
            path.to_str().unwrap()
        )
        .into());
    }

    let mut wtr = csv::Writer::from_path(path.to_str().unwrap())?;
    wtr.write_record(HEADER)
        .expect("Write failed when try to insert header row.");

    let pb = ProgressBar::new(logs.len() as u64);
    for i in logs {
        let mut row = vec![];

        // control bits / flags
        let mut flags = vec![];
        if i.syn {
            flags.push("SYN");
        }
        if i.ack {
            flags.push("ACK");
        }
        if i.fin {
            flags.push("FIN");
        }
        if i.rst {
            flags.push("RST");
        }
        if i.psh {
            flags.push("PSH");
        }
        if i.cwr {
            flags.push("CWR");
        }

        // should push by "HEADER" order
        row.push(i.month.to_string());
        row.push(i.day.to_string());
        row.push(i.time);
        row.push(i.hostname);
        row.push(i.uptime);
        row.push(i.event);
        row.push(i.r#in);
        row.push(i.out);
        row.push(i.mac);
        row.push(i.src);
        row.push(i.dst);
        row.push(i.len.to_string());
        row.push(i.tos.unwrap_or("".to_string()));
        row.push(i.prec.unwrap_or("".to_string()));
        row.push(unwrap_or_empty_then_to_string(i.ttl));
        row.push(unwrap_or_empty_then_to_string(i.id));
        row.push(if i.df {
            "DF".to_string()
        } else {
            "".to_string()
        });
        row.push(i.proto);
        row.push(unwrap_or_empty_then_to_string(i.spt));
        row.push(unwrap_or_empty_then_to_string(i.dpt));
        row.push(unwrap_or_empty_then_to_string(i.window));
        row.push(i.res);
        row.push(flags.join(" "));
        row.push(
            // The value follows the flag, so it is empty when it does not appear, and it depends on the record value when it appears
            if i.urgp.is_some() {
                if i.urgp.unwrap() {
                    "1"
                } else {
                    "0"
                }
            } else {
                ""
            }
            .to_string(),
        );
        row.push(unwrap_or_empty_then_to_string(i.tc));
        row.push(unwrap_or_empty_then_to_string(i.hoplimit));
        row.push(unwrap_or_empty_then_to_string(i.flowbl));
        row.push(unwrap_or_empty_then_to_string(i.r#type));
        row.push(unwrap_or_empty_then_to_string(i.code));
        row.push(unwrap_or_empty_then_to_string(i.seq));
        row.push(unwrap_or_empty_then_to_string(i.mtu));
        row.push(unwrap_or_empty_then_to_string(i.mark));
        row.push(unwrap_or_empty_then_to_string(i.physin));
        row.push(unwrap_or_empty_then_to_string(i.phyout));
        row.push(i.origin.to_owned());

        wtr.write_record(row).expect("Write csv file occur error");

        pb.inc(1); // increase progress bar
    }
    pb.finish();

    Ok(())
}

/// If value is none, return empty string, else return value that convert to string
fn unwrap_or_empty_then_to_string<T: ToString>(value: Option<T>) -> String {
    if value.is_some() {
        return value.unwrap().to_string();
    }
    "".to_string()
}

#[cfg(test)]
mod tests {
    mod test_unwrap_or_empty_then_to_string {
        use super::super::unwrap_or_empty_then_to_string;

        #[test]
        fn test_input_none() {
            assert_eq!(
                unwrap_or_empty_then_to_string::<String>(None),
                "".to_string()
            );
        }

        #[test]
        fn test_input_unsigned_integer() {
            assert_eq!(unwrap_or_empty_then_to_string(Some(443)), "443".to_string());
        }

        #[test]
        fn test_input_singed_integer() {
            assert_eq!(unwrap_or_empty_then_to_string(Some(-1)), "-1".to_string());
        }
    }
}
