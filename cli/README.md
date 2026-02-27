# ufwlog-cli

A CLI program to parse, format and export ufw log.

## Usage

Download binary from [release](https://github.com/hms5232/ufwlog/releases), or clone project run with cargo.

### Export

Current only support export to csv:

```
ufwlog export -l [log path] --output [filename, default: ufwlog.csv] 
```

the `--log-path` default is `/var/log/ufw.log` on Linux; `./ufw.log` on Windows and macOS.

## LICENSE

[MPL 2.0](../LICENSE)
