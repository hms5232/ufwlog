# ufwlog

[![Crates.io Version](https://img.shields.io/crates/v/ufwlog?style=flat-square)](https://crates.io/crates/ufwlog)

A program to parse, format and export ufw log.

> Please see [here](./cli/README.md) for CLI README. 

## Installation

```shell
cargo add ufwlog
```

## Usage

The `UfwLog` struct is a parsed log record. You can use it to filter, export, etc.

See [quick start](https://docs.rs/ufwlog/#quick-start) part to get started, or [docs.rs](https://docs.rs/ufwlog) for full API docs.

## Reporting

Because reference of UFW log is too few and some difference between version, config, etc. this program may have something uncovered.

If you find any problem, just create an issue with original log.

You may mask, redact, or sanitize sensitive data in the logs, but please keep the original data type/format. Incorrect types can easily lead to misdiagnosis.

For example, if a new field `FID=5232` is reported as `FID=XXXX`, it might be interpreted as a string because of `X` char. Instead, you can sanitize it to `FID=1234` so that the data type remains the same as original log.

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

or use alias `rc` (abbreviation of `run cli`):

```
cargo rc -- [parameters]
```

## LICENSE

[MPL 2.0](LICENSE)
