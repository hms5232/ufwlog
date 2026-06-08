# ufwlog

[![Crates.io Version](https://img.shields.io/crates/v/ufwlog?style=flat-square)](https://crates.io/crates/ufwlog)

A program to parse, format and export ufw log.

> Please see [here](./cli/README.md) for CLI README. 

## Installation

```shell
cargo install ufwlog
```

## Usage

```rust
fn main() {
    // input log path then get a vec contains UfwLog struct
    let logs: Vec<ufwlog::UfwLog> = ufwlog::Ufwlog::from_file("./ufw.log").unwrap();
    // filter record
    let filtered = logs
        .iter()
        .filter(|log| log.event == ufwlog::LoggedEvent::Block) // only block event
        .filter(|log| log.src == "127.0.0.1") // package from 127.0.0.1
        .collect::<Vec<&ufwlog::UfwLog>>();

    // export to csv file
    let csv_exporter = ufwlog::export::csv::Exporter;
    csv_exporter.export(filtered,  &mut std::io::stdout()); // print csv content to stdout
}
```

## Reporting

Because reference of UFW log is too few and some difference between version, config, etc. this program may have something uncovered.

If you find any problem, just create an issue with original log.

You can de-identification original log content, but keep type. Otherwise, it will make me make mistake judgment. For example, if a new field `FID=5232` changed to `FID=XXXX` when reporting, I will add `FID` as string because of `X` char. In this case, you can change record to `FID=1234` because data type is same as origin log.

## Developing

```shell
cargo fmt
cargo clippy
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

Also, you can use [prek](https://prek.j178.dev/) to check code/files before committing:

```shell
prek install # install pre-commit hooks
prek run # run all hooks
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
