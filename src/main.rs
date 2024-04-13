mod csv;
mod parser;

fn main() {
    let mut ufw_log_map = vec![];
    let log_by_line = parser::read_lines("./ufw.log"); // TODO: accept path flag/argument
    for i in 0..log_by_line.len() {
        let map = parser::to_hashmap(&log_by_line[i]);
        ufw_log_map.push(map);
    }
    crate::csv::convert(ufw_log_map, None).unwrap();
}
