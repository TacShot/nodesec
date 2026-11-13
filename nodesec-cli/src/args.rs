use clap::Parser;
use nodesec_core::Platform;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(name = "nodesec", version, about = "Cross-platform System & Network Security Platform", long_about = None)]
pub struct Args {
    #[arg(long, value_enum, default_value = "auto")]
    pub target_os: TargetOs,

    #[arg(long, value_enum, default_value = "text")]
    pub format: OutputFormat,

    #[arg(long)]
    pub include_cves: bool,

    #[arg(long, default_value = "3")]
    pub results_per_finding: usize,

    #[arg(long, default_value = "artifacts")]
    pub output_dir: PathBuf,

    #[arg(long)]
    pub generate_remediation: bool,

    #[arg(long)]
    pub save_to_desktop: bool,

    #[arg(long)]
    pub scan_apps: bool,

    #[arg(long, default_value = "25")]
    pub app_limit: usize,

    #[arg(long, value_enum)]
    pub standard: Vec<ComplianceStandard>,

    #[arg(long)]
    pub cleanup: bool,

    // New features
    #[arg(long)]
    pub collect_logs: bool,

    #[arg(long, default_value = "24")]
    pub log_hours: i64,

    #[arg(long)]
    pub scan_ad: bool,

    // Interactive mode
    #[arg(long, short = 'i')]
    pub interactive: bool,

    // Launch TUI
    #[arg(long)]
    pub tui: bool,

    // Launch GUI
    #[arg(long)]
    pub gui: bool,
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq)]
pub enum TargetOs {
    Auto,
    Linux,
    MacOS,
    Windows,
}

impl From<TargetOs> for Option<Platform> {
    fn from(v: TargetOs) -> Self {
        match v {
            TargetOs::Auto => None,
            TargetOs::Linux => Some(Platform::Linux),
            TargetOs::MacOS => Some(Platform::MacOS),
            TargetOs::Windows => Some(Platform::Windows),
        }
    }
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq)]
pub enum ComplianceStandard {
    ISO27001,
    HIPAA,
    PCIDSS,
}

impl From<ComplianceStandard> for String {
    fn from(v: ComplianceStandard) -> Self {
        match v {
            ComplianceStandard::ISO27001 => "ISO27001".to_string(),
            ComplianceStandard::HIPAA => "HIPAA".to_string(),
            ComplianceStandard::PCIDSS => "PCI_DSS".to_string(),
        }
    }
}