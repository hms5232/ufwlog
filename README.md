# ufwlog
A program to parse, format and export ufw log.

## Usage

### CLI

See [here](./cli/README.md).

### Library crate

```rust
fn main() {
    // input log path then get a vec contains UfwLog struct
    let logs = ufwlog::parser::get_ufwlog_vec("./ufw.log");
    // filter record
    let filtered = logs
        .iter()
        .filter(|log| log.event == ufwlog::LoggedEvent::Block) // only block event
        .filter(|log| log.src == "127.0.0.1") // package from 127.0.0.1
        .collect::<Vec<_>>();
    
    // export to csv file
    let csv_header = ufwlog::CSV_HEADER;
    // write header row here
    for log in filtered {
        let row = log.to_csv_vec();
        // write row here
    }
    // save csv file here
}
```

## Reporting

Because reference of UFW log is too few and some difference between version, config, etc. this program may have something uncovered.

If you find any problem, just create an issue with original log.

You can de-identification original log content, but keep type. Otherwise, it will make me make mistake judgment. For example, if a new field `FID=5232` changed to `FID=XXXX` when reporting, I will add `FID` as string because of `X` char. In this case, you can change record to `FID=1234` because data type is same as origin log.

## Developing

```
cargo fmt
```

run test:

```shell
cargo test --workspace # all
cargo test -p ufwlog # library
cargo test -p ufwlog-cli # binary
```

Check workspace struct:

```
cargo tree --workspace
```

### Library

```
cargo check --lib
```

### Binary

```
cargo run -p ufwlog-cli -- [parameters]
```

You can omit the `-p` part because of default members setting.

## LICENSE

[MPL 2.0](LICENSE)
