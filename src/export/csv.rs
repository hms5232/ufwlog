use crate::ufw_log::UfwLog;

/// csv header
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

impl UfwLog {
    /// Get a vector for csv order.
    pub fn to_csv_vec(&self) -> Vec<String> {
        let mut row = vec![];

        // control bits / flags
        let mut flags = vec![];
        if self.syn {
            flags.push("SYN");
        }
        if self.ack {
            flags.push("ACK");
        }
        if self.fin {
            flags.push("FIN");
        }
        if self.rst {
            flags.push("RST");
        }
        if self.psh {
            flags.push("PSH");
        }
        if self.cwr {
            flags.push("CWR");
        }

        // should push by "HEADER" order
        row.push(self.month.to_string());
        row.push(self.day.to_string());
        row.push(self.time.clone());
        row.push(self.hostname.clone());
        row.push(self.uptime.clone());
        row.push(self.event.to_string());
        row.push(self.r#in.clone());
        row.push(self.out.clone());
        row.push(self.mac.clone());
        row.push(self.src.clone());
        row.push(self.dst.clone());
        row.push(self.len.to_string());
        row.push(self.tos.clone().unwrap_or("".to_string()));
        row.push(self.prec.clone().unwrap_or("".to_string()));
        row.push(unwrap_or_empty_then_to_string(self.ttl));
        row.push(unwrap_or_empty_then_to_string(self.id));
        row.push(if self.df {
            "DF".to_string()
        } else {
            "".to_string()
        });
        row.push(self.proto.clone());
        row.push(unwrap_or_empty_then_to_string(self.spt));
        row.push(unwrap_or_empty_then_to_string(self.dpt));
        row.push(unwrap_or_empty_then_to_string(self.window));
        row.push(self.res.clone());
        row.push(flags.join(" "));
        row.push(
            // The value follows the flag, so it is empty when it does not appear, and it depends on the record value when it appears
            if self.urgp.is_some() {
                if self.urgp.unwrap() {
                    "1"
                } else {
                    "0"
                }
            } else {
                ""
            }
            .to_string(),
        );
        row.push(unwrap_or_empty_then_to_string(self.tc));
        row.push(unwrap_or_empty_then_to_string(self.hoplimit));
        row.push(unwrap_or_empty_then_to_string(self.flowlbl));
        row.push(unwrap_or_empty_then_to_string(self.r#type));
        row.push(unwrap_or_empty_then_to_string(self.code.clone()));
        row.push(unwrap_or_empty_then_to_string(self.seq));
        row.push(unwrap_or_empty_then_to_string(self.mtu));
        row.push(unwrap_or_empty_then_to_string(self.mark.clone()));
        row.push(unwrap_or_empty_then_to_string(self.physin.clone()));
        row.push(unwrap_or_empty_then_to_string(self.phyout.clone()));
        row.push(self.origin.clone());

        row
    }
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
