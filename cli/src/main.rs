#![forbid(unsafe_code)]

//! The `studge` command-line client.

mod app;
mod commands;
mod config;
mod session;
mod vault_util;
use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "studge", version, about = "Studge Pass command-line client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Init {
        #[arg(long)]
        relay: Option<String>,
        #[arg(long)]
        folder: Option<String>,
    },
    Login,
    Unlock,
    Lock,
    Status,
    Sync,
    List {
        #[arg(long)]
        vault: Option<String>,
    },
    Get {
        query: String,
        #[arg(long)]
        field: Option<String>,
        #[arg(long)]
        print: bool,
    },
    Add {
        #[command(subcommand)]
        kind: AddKind,
    },
    Edit {
        query: String,
    },
    Rm {
        query: String,
    },
    Generate {
        #[arg(long, default_value_t = 20)]
        length: usize,
        #[arg(long)]
        symbols: bool,
        #[arg(long)]
        no_symbols: bool,
    },
    Totp {
        query: String,
    },
    Import {
        format: String,
        file: String,
    },
    Export {
        format: String,
        file: String,
        #[arg(long)]
        i_understand_this_is_plaintext: bool,
    },
    Health,
    Devices {
        #[command(subcommand)]
        action: DeviceAction,
    },
    Config,
}

#[derive(Debug, Subcommand)]
enum AddKind {
    Login,
}

#[derive(Debug, Subcommand)]
enum DeviceAction {
    List,
    Revoke { device: String },
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Init { relay, folder } => commands::init::run(relay, folder),
        Command::Login => commands::login::run(),
        Command::Unlock => commands::unlock::run(),
        Command::Lock => commands::lock::run(),
        Command::Status => commands::status::run(),
        Command::Sync => commands::sync::run(),
        Command::List { vault } => commands::list::run(vault),
        Command::Get {
            query,
            field,
            print,
        } => commands::get::run(query, field, print),
        Command::Add { kind } => match kind {
            AddKind::Login => commands::add_login::run(),
        },
        Command::Edit { query } => commands::edit::run(query),
        Command::Rm { query } => commands::rm::run(query),
        Command::Generate {
            length,
            symbols,
            no_symbols,
        } => commands::generate::run(length, symbols, no_symbols),
        Command::Totp { query } => commands::totp::run(query),
        Command::Import { format, file } => commands::import::run(format, file),
        Command::Export {
            format,
            file,
            i_understand_this_is_plaintext,
        } => commands::export::run(format, file, i_understand_this_is_plaintext),
        Command::Health => commands::health::run(),
        Command::Devices { action } => match action {
            DeviceAction::List => commands::devices::list(),
            DeviceAction::Revoke { device } => commands::devices::revoke(device),
        },
        Command::Config => commands::config::run(),
    }
}
