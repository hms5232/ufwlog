# ufwlog
A program to parse, format and export ufw log.

## Usage

Download binary from [release](https://github.com/hms5232/ufwlog/releases), or clone project run with cargo.

### Export

Current only support export to csv:

```
ufwlog export -l [log path] --output [filename, default: ufwlog.csv] 
```

the `--log-path` default is `/var/log/ufw.log` on Linux; `./ufw.log` on Windows and macOS.

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
