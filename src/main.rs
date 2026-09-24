// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

mod cli;
mod coserv;
mod display;
mod error;
mod evidence;
mod fetch;
mod scheme;
mod store;
mod submit;
mod utils;
mod verify;

use clap::Parser;
use cli::{Cli, Cmd};
use log::{error, info};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args = Cli::parse();

    env_logger::builder()
        .filter_level(args.verbosity.log_level_filter())
        .init();

    let status = match args.command {
        Cmd::Display(subcmd) => display::cmd(subcmd),
        Cmd::Fetch(subcmd) => fetch::cmd(subcmd),
        Cmd::Submit(subcmd) => submit::cmd(subcmd),
        Cmd::Verify(subcmd) => verify::cmd(subcmd),
    };

    match status {
        Ok(()) => {
            info!("done.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("{e}");
            ExitCode::FAILURE
        }
    }
}
