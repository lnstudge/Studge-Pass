#![forbid(unsafe_code)]

//! The `studge` command-line client. Phase 0 wires `--version`; the commands
//! arrive in Phase 6.

use clap::Parser;

/// Studge Pass command-line client.
#[derive(Debug, Parser)]
#[command(name = "studge", version, about = "Studge Pass command-line client")]
struct Cli {}

fn main() {
    // Phase 6 adds commands; parsing already gives us --version and --help.
    let _cli = Cli::parse();
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn version_is_wired() {
        assert!(Cli::command().get_version().is_some());
    }
}
