//! Legacy-compatible `hxscan` binary alias entry point.
#![forbid(unsafe_code)]

use std::env;
use std::io::{self, IsTerminal, Write};
use std::process;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() && io::stdin().is_terminal() {
        process::exit(tcpscan::run_interactive_shell());
    }

    let (exit_code, stdout_str, stderr_str) = tcpscan::run_from_args(&args);

    if !stderr_str.is_empty() {
        let _ = io::stderr().write_all(stderr_str.as_bytes());
    }
    if !stdout_str.is_empty() {
        let _ = io::stdout().write_all(stdout_str.as_bytes());
    }

    process::exit(exit_code);
}
