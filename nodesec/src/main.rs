use clap::{Parser, Subcommand};
use anyhow::Result;
use std::process::Command;

#[derive(Parser, Debug)]
#[command(name = "nodesec", version, about = "Cross-platform System & Network Security Platform")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run audit with CLI arguments
    Run(nodesec_cli::Args),
    /// Launch terminal UI
    Tui,
    /// Launch graphical UI
    Gui,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run(args) => {
            // Use the CLI crate's main logic
            nodesec_cli::run_with_args(args)?
        }
        Commands::Tui => {
            let status = Command::new("cargo")
                .args(["run", "--bin", "nodesec-tui"])
                .current_dir("/Users/tac/nodesec")
                .status()?;
            if !status.success() {
                anyhow::bail!("TUI exited with error");
            }
        }
        Commands::Gui => {
            let status = Command::new("cargo")
                .args(["run", "--bin", "nodesec-gui"])
                .current_dir("/Users/tac/nodesec")
                .status()?;
            if !status.success() {
                anyhow::bail!("GUI exited with error");
            }
        }
    }
    Ok(())
}