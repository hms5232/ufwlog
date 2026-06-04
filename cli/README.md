# ufwlog-cli

[![GitHub Release](https://img.shields.io/github/v/release/hms5232/ufwlog?include_prereleases&style=flat-square)](https://github.com/hms5232/ufwlog/releases)

A CLI program to parse, format and export ufw log.

## Installation

Download from [GitHub Release](https://github.com/hms5232/ufwlog/releases).

## Usage

Download binary from [release](https://github.com/hms5232/ufwlog/releases), or clone project run with cargo.

### Export

Current only support export to csv:

```
ufwlog export -l [log path] --output [filename, default: ufwlog.csv] 
```

the `--log-path` default is `/var/log/ufw.log` on Linux; `./ufw.log` on Windows and macOS.

## Developing

See [README of library crate](../README.md#developing).

## LICENSE

[MPL 2.0](../LICENSE)
