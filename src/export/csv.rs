use crate::error::Error;
use crate::ufw_log::UfwLog;
use std::io::Write;

/// csv header
///
/// Recommend use [get_header()](Exporter::get_header) to get it.
pub const HEADER: [&str; 35] = [
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

/// Exporter for csv format
pub struct Exporter;

impl super::Export for Exporter {
    fn get_extension(&self) -> &'static str {
        "csv"
    }

    fn convert(&self, log: &UfwLog) -> Result<String, Error> {
        Ok(self.get_csv_row(log).join(",").to_string())
    }

    fn export(&self, logs: &[UfwLog], writer: &mut dyn Write) -> Result<(), Error> {
        writeln!(writer, "{}", self.get_header().join(","))?;
        for log in logs {
            match self.convert(log) {
                Ok(c) => writeln!(writer, "{}", c)?,
                Err(e) => return Err(e),
            }
        }
        Ok(writer.flush()?)
    }
}

impl Exporter {
    /// Get the header of output csv
    ///
    /// # Examples
    ///
    /// ```rust
    /// let export = ufwlog::export::csv::Exporter;
    /// assert_eq!(export.get_header(), ["Month", "Day", "Time", "hostname", "uptime", "event", "IN", "OUT", "MAC", "SRC", "DST", "LEN", "TOS", "PREC", "TTL", "ID", "DF", "PROTO", "SPT", "DPT", "WINDOW", "RES", "Control Bits / flags", "URGP", "TC", "HOPLIMIT", "FLOWLBL", "TYPE", "CODE", "SEQ", "MTU", "MARK", "PHYSIN", "PHYOUT", "origin"])
    /// ```
    pub fn get_header(&self) -> [&'static str; 35] {
        HEADER
    }

    /// Get a vector of strings that represent a log in csv format order
    pub fn get_csv_row(&self, log: &UfwLog) -> Vec<String> {
        let mut row = vec![];

        // control bits / flags
        let mut flags = vec![];
        if log.syn {
            flags.push("SYN");
        }
        if log.ack {
            flags.push("ACK");
        }
        if log.fin {
            flags.push("FIN");
        }
        if log.rst {
            flags.push("RST");
        }
        if log.psh {
            flags.push("PSH");
        }
        if log.cwr {
            flags.push("CWR");
        }

        // should push by "HEADER" order
        row.push(log.month.to_string());
        row.push(log.day.to_string());
        row.push(log.time.clone());
        row.push(log.hostname.clone());
        row.push(log.uptime.clone());
        row.push(log.event.to_string());
        row.push(log.r#in.clone());
        row.push(log.out.clone());
        row.push(log.mac.clone());
        row.push(log.src.clone());
        row.push(log.dst.clone());
        row.push(log.len.to_string());
        row.push(log.tos.clone().unwrap_or("".to_string()));
        row.push(log.prec.clone().unwrap_or("".to_string()));
        row.push(unwrap_or_empty_then_to_string(log.ttl));
        row.push(unwrap_or_empty_then_to_string(log.id));
        row.push(if log.df {
            "DF".to_string()
        } else {
            "".to_string()
        });
        row.push(log.proto.clone());
        row.push(unwrap_or_empty_then_to_string(log.spt));
        row.push(unwrap_or_empty_then_to_string(log.dpt));
        row.push(unwrap_or_empty_then_to_string(log.window));
        row.push(log.res.clone());
        row.push(flags.join(" "));
        row.push(
            // The value follows the flag, so it is empty when it does not appear, and it depends on the record value when it appears
            if log.urgp.is_some() {
                if log.urgp.unwrap() {
                    "1"
                } else {
                    "0"
                }
            } else {
                ""
            }
            .to_string(),
        );
        row.push(unwrap_or_empty_then_to_string(log.tc));
        row.push(unwrap_or_empty_then_to_string(log.hoplimit));
        row.push(unwrap_or_empty_then_to_string(log.flowlbl));
        row.push(unwrap_or_empty_then_to_string(log.r#type));
        row.push(unwrap_or_empty_then_to_string(log.code.clone()));
        row.push(unwrap_or_empty_then_to_string(log.seq));
        row.push(unwrap_or_empty_then_to_string(log.mtu));
        row.push(unwrap_or_empty_then_to_string(log.mark.clone()));
        row.push(unwrap_or_empty_then_to_string(log.physin.clone()));
        row.push(unwrap_or_empty_then_to_string(log.phyout.clone()));
        row.push(log.get_origin().to_string());

        row
    }
}

/// If value is none, return empty string, else return value that convert to string
fn unwrap_or_empty_then_to_string<T: ToString>(value: Option<T>) -> String {
    value.map_or("".to_string(), |v| v.to_string())
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
