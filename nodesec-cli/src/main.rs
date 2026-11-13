use nodesec_cli::run_with_args;
use nodesec_cli::Args;
use clap::Parser;

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    run_with_args(args)
}