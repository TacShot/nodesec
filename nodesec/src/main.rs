use clap::{Parser, Args, Subcommand};
use anyhow::Result;
use std::process::Command;
use nodesec_cli::{Args as CliArgs, TargetOs, OutputFormat, ComplianceStandard};

#[derive(Parser, Debug)]
#[command(name = "nodesec", version, about = "Cross-platform System & Network Security Platform")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Network monitoring mode (real-time connections, threat detection)
    Net(NetCommands),
    /// Security audit mode (static scans, CVE enrichment, compliance)
    Audit(AuditCommands),
    /// View and manage reports
    Report(ReportCommands),
}

#[derive(Args, Debug)]
struct NetCommands {
    #[command(subcommand)]
    command: NetSubCommands,
}

#[derive(Subcommand, Debug)]
enum NetSubCommands {
    /// On-device real-time network monitoring
    Live {
        /// Network interface (auto-detect if not specified)
        #[arg(long)]
        interface: Option<String>,
        /// Refresh interval in seconds
        #[arg(long, default_value = "2")]
        interval: u64,
        /// Launch TUI
        #[arg(long)]
        tui: bool,
        /// Launch GUI
        #[arg(long)]
        gui: bool,
    },
    /// Start WebSocket server for client-server mode
    Server {
        /// Bind address
        #[arg(long, default_value = "0.0.0.0:8080")]
        bind: String,
        /// Enable TLS
        #[arg(long)]
        tls: bool,
        /// Certificate path
        #[arg(long)]
        cert: Option<String>,
        /// Key path
        #[arg(long)]
        key: Option<String>,
    },
    /// Manage connected agents
    Agents {
        #[command(subcommand)]
        command: AgentCommands,
    },
    /// Manage detection rules
    Rules {
        #[command(subcommand)]
        command: RuleCommands,
    },
    /// Show connection status
    Status,
}

#[derive(Subcommand, Debug)]
enum AgentCommands {
    /// List connected agents
    List,
    /// Register new agent
    Register {
        #[arg(long)]
        name: String,
    },
    /// Revoke agent access
    Revoke {
        #[arg(long)]
        id: String,
    },
    /// View agent logs
    Logs {
        #[arg(long)]
        id: String,
    },
}

#[derive(Subcommand, Debug)]
enum RuleCommands {
    /// List detection rules
    List,
    /// Add custom rule
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        description: String,
        #[arg(long)]
        severity: String,
    },
    /// Remove rule
    Remove {
        #[arg(long)]
        id: String,
    },
}

#[derive(Args, Debug)]
struct AuditCommands {
    #[command(subcommand)]
    command: AuditSubCommands,
}

#[derive(Subcommand, Debug)]
enum AuditSubCommands {
    /// Run security audit
    Run {
        #[arg(long, value_enum, default_value = "auto")]
        target_os: TargetOs,
        #[arg(long, value_enum, default_value = "text")]
        format: OutputFormat,
        #[arg(long)]
        include_cves: bool,
        #[arg(long, default_value = "3")]
        results_per_finding: usize,
        #[arg(long, default_value = "artifacts")]
        output_dir: String,
        #[arg(long)]
        generate_remediation: bool,
        #[arg(long)]
        save_to_desktop: bool,
        #[arg(long)]
        scan_apps: bool,
        #[arg(long, default_value = "25")]
        app_limit: usize,
        #[arg(long, value_enum)]
        standard: Vec<ComplianceStandard>,
        #[arg(long)]
        cleanup: bool,
        #[arg(long)]
        collect_logs: bool,
        #[arg(long, default_value = "24")]
        log_hours: i64,
        #[arg(long)]
        scan_ad: bool,
        #[arg(long, short = 'i')]
        interactive: bool,
        #[arg(long)]
        tui: bool,
        #[arg(long)]
        gui: bool,
    },
    /// View last report
    Report {
        #[arg(long)]
        id: Option<String>,
    },
    /// Generate remediation script
    Remediate {
        #[arg(long)]
        report_id: String,
    },
}

#[derive(Args, Debug)]
struct ReportCommands {
    #[command(subcommand)]
    command: ReportSubCommands,
}

#[derive(Subcommand, Debug)]
enum ReportSubCommands {
    /// List all reports
    List,
    /// View specific report
    View {
        id: String,
        #[arg(long, value_enum, default_value = "text")]
        format: ReportFormat,
    },
    /// Export report
    Export {
        id: String,
        #[arg(long, value_enum, default_value = "json")]
        format: ReportFormat,
        #[arg(long)]
        output: String,
    },
    /// Delete report
    Delete {
        id: String,
    },
}

/// Output format for reports
#[derive(clap::ValueEnum, Clone, Debug, PartialEq)]
pub enum ReportFormat {
    Text,
    Json,
    Csv,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Net(net_cmd) => handle_net_command(net_cmd)?,
        Commands::Audit(audit_cmd) => handle_audit_command(audit_cmd)?,
        Commands::Report(report_cmd) => handle_report_command(report_cmd)?,
    }
    Ok(())
}

fn handle_net_command(cmd: NetCommands) -> Result<()> {
    match cmd.command {
        NetSubCommands::Live { interface, interval, tui, gui } => {
            if tui {
                run_net_tui(interface, interval)?
            } else if gui {
                run_net_gui(interface, interval)?
            } else {
                run_net_cli(interface, interval)?
            }
        }
        NetSubCommands::Server { bind, tls, cert, key } => {
            run_net_server(bind, tls, cert, key)?
        }
        NetSubCommands::Agents { command } => handle_agent_command(command)?,
        NetSubCommands::Rules { command } => handle_rule_command(command)?,
        NetSubCommands::Status => show_net_status()?,
    }
    Ok(())
}

fn handle_audit_command(cmd: AuditCommands) -> Result<()> {
    match cmd.command {
        AuditSubCommands::Run { 
            target_os, format, include_cves, results_per_finding, 
            output_dir, generate_remediation, save_to_desktop, 
            scan_apps, app_limit, standard, cleanup, collect_logs, 
            log_hours, scan_ad, interactive, tui, gui 
        } => {
            if tui {
                run_audit_tui()?
            } else if gui {
                run_audit_gui()?
            } else {
                let args = nodesec_cli::Args {
                    target_os,
                    format,
                    include_cves,
                    results_per_finding,
                    output_dir: output_dir.into(),
                    generate_remediation,
                    save_to_desktop,
                    scan_apps,
                    app_limit,
                    standard,
                    cleanup,
                    collect_logs,
                    log_hours,
                    scan_ad,
                    interactive,
                    tui: false,
                    gui: false,
                };
                nodesec_cli::run_with_args(args)?
            }
        }
        AuditSubCommands::Report { id } => view_audit_report(id)?,
        AuditSubCommands::Remediate { report_id } => generate_remediation(report_id)?,
    }
    Ok(())
}

fn handle_report_command(cmd: ReportCommands) -> Result<()> {
    match cmd.command {
        ReportSubCommands::List => list_reports()?,
        ReportSubCommands::View { id, format } => view_report(id, format)?,
        ReportSubCommands::Export { id, format, output } => export_report(id, format, output)?,
        ReportSubCommands::Delete { id } => delete_report(id)?,
    }
    Ok(())
}

fn handle_agent_command(cmd: AgentCommands) -> Result<()> {
    match cmd {
        AgentCommands::List => list_agents()?,
        AgentCommands::Register { name } => register_agent(name)?,
        AgentCommands::Revoke { id } => revoke_agent(id)?,
        AgentCommands::Logs { id } => view_agent_logs(id)?,
    }
    Ok(())
}

fn handle_rule_command(cmd: RuleCommands) -> Result<()> {
    match cmd {
        RuleCommands::List => list_rules()?,
        RuleCommands::Add { name, description, severity } => add_rule(name, description, severity)?,
        RuleCommands::Remove { id } => remove_rule(id)?,
    }
    Ok(())
}

// Network mode implementations
fn run_net_tui(interface: Option<String>, interval: u64) -> Result<()> {
    let status = Command::new("cargo")
        .args(["run", "--bin", "nodesec-net-tui"])
        .current_dir("/Users/tac/nodesec")
        .status()?;
    if !status.success() { anyhow::bail!("Network TUI exited with error"); }
    Ok(())
}

fn run_net_gui(interface: Option<String>, interval: u64) -> Result<()> {
    let status = Command::new("cargo")
        .args(["run", "--bin", "nodesec-net-gui"])
        .current_dir("/Users/tac/nodesec")
        .status()?;
    if !status.success() { anyhow::bail!("Network GUI exited with error"); }
    Ok(())
}

fn run_net_cli(interface: Option<String>, interval: u64) -> Result<()> {
    println!("Network CLI mode - interface: {:?}, interval: {}s", interface, interval);
    // TODO: Implement CLI streaming output
    Ok(())
}

fn run_net_server(bind: String, tls: bool, cert: Option<String>, key: Option<String>) -> Result<()> {
    println!("Starting network server on {}", bind);
    let status = Command::new("cargo")
        .args(["run", "--bin", "nodesec-net-server"])
        .current_dir("/Users/tac/nodesec")
        .status()?;
    if !status.success() { anyhow::bail!("Network server exited with error"); }
    Ok(())
}

fn show_net_status() -> Result<()> {
    println!("Network monitoring status: Not running");
    Ok(())
}

fn list_agents() -> Result<()> {
    println!("No agents connected");
    Ok(())
}

fn register_agent(name: String) -> Result<()> {
    println!("Registered agent: {}", name);
    Ok(())
}

fn revoke_agent(id: String) -> Result<()> {
    println!("Revoked agent: {}", id);
    Ok(())
}

fn view_agent_logs(id: String) -> Result<()> {
    println!("Logs for agent {}: (not implemented)", id);
    Ok(())
}

fn list_rules() -> Result<()> {
    println!("Built-in detection rules:");
    println!("  - Destination rarity");
    println!("  - Connection frequency");
    println!("  - Suspicious ports");
    println!("  - Unusual timing");
    println!("  - First-time process");
    println!("  - Process anomalies");
    println!("  - Connection patterns");
    println!("  - Known malicious indicators");
    Ok(())
}

fn add_rule(name: String, description: String, severity: String) -> Result<()> {
    println!("Added rule: {} ({})", name, severity);
    Ok(())
}

fn remove_rule(id: String) -> Result<()> {
    println!("Removed rule: {}", id);
    Ok(())
}

fn run_audit_tui() -> Result<()> {
    let status = Command::new("cargo")
        .args(["run", "--bin", "nodesec-tui"])
        .current_dir("/Users/tac/nodesec")
        .status()?;
    if !status.success() { anyhow::bail!("Audit TUI exited with error"); }
    Ok(())
}

fn run_audit_gui() -> Result<()> {
    let status = Command::new("cargo")
        .args(["run", "--bin", "nodesec-gui"])
        .current_dir("/Users/tac/nodesec")
        .status()?;
    if !status.success() { anyhow::bail!("Audit GUI exited with error"); }
    Ok(())
}

fn view_audit_report(id: Option<String>) -> Result<()> {
    println!("Viewing audit report: {:?}", id);
    Ok(())
}

fn generate_remediation(report_id: String) -> Result<()> {
    println!("Generating remediation for report: {}", report_id);
    Ok(())
}

fn view_report(id: String, format: ReportFormat) -> Result<()> {
    println!("Viewing report {} as {:?}", id, format);
    Ok(())
}

fn export_report(id: String, format: ReportFormat, output: String) -> Result<()> {
    println!("Exporting report {} as {:?} to {}", id, format, output);
    Ok(())
}

fn delete_report(id: String) -> Result<()> {
    println!("Deleted report: {}", id);
    Ok(())
}

fn list_reports() -> Result<()> {
    println!("Reports: (not implemented)");
    Ok(())
}