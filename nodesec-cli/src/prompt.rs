use std::io::{self, Write};
use colored::*;
use nodesec_core::Platform;

pub fn prompt_target_os() -> anyhow::Result<Option<Platform>> {
    println!("{}", "Select target platform:".bold());
    println!("  1) Auto-detect");
    println!("  2) Linux");
    println!("  3) macOS");
    println!("  4) Windows");
    print!("Choice [1]: ");
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let choice = input.trim();
    
    match choice {
        "1" | "" => Ok(None),
        "2" => Ok(Some(Platform::Linux)),
        "3" => Ok(Some(Platform::MacOS)),
        "4" => Ok(Some(Platform::Windows)),
        _ => {
            println!("{}", "Invalid choice, using auto-detect".yellow());
            Ok(None)
        }
    }
}

pub fn prompt_yes_no(prompt: &str, default: bool) -> anyhow::Result<bool> {
    let default_str = if default { "Y/n" } else { "y/N" };
    print!("{} [{}]: ", prompt.bold(), default_str);
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();
    
    if input.is_empty() {
        Ok(default)
    } else {
        Ok(input.starts_with('y'))
    }
}

pub fn prompt_number(prompt: &str, default: i64, min: i64, max: i64) -> anyhow::Result<i64> {
    print!("{} [{}]: ", prompt.bold(), default);
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();
    
    if input.is_empty() {
        Ok(default)
    } else {
        match input.parse::<i64>() {
            Ok(n) if n >= min && n <= max => Ok(n),
            _ => {
                println!("{}", format!("Invalid number, using default: {}", default).yellow());
                Ok(default)
            }
        }
    }
}

pub fn prompt_format() -> anyhow::Result<crate::args::OutputFormat> {
    use crate::args::OutputFormat;
    println!("\n{}", "Output format:".bold());
    println!("  1) Text (human-readable)");
    println!("  2) JSON (machine-readable)");
    print!("Choice [1]: ");
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    match input.trim() {
        "2" => Ok(OutputFormat::Json),
        _ => Ok(OutputFormat::Text),
    }
}

pub fn prompt_standards() -> anyhow::Result<Option<Vec<String>>> {
    println!("\n{}", "Compliance standards (space-separated, e.g. 'ISO27001 HIPAA'):".bold());
    println!("  Available: ISO27001, HIPAA, PCI_DSS");
    print!("Standards [none]: ");
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();
    
    if input.is_empty() {
        Ok(None)
    } else {
        let standards: Vec<String> = input.split_whitespace()
            .map(|s| s.to_uppercase())
            .filter(|s| matches!(s.as_str(), "ISO27001" | "HIPAA" | "PCI_DSS"))
            .collect();
        if standards.is_empty() {
            println!("{}", "No valid standards selected".yellow());
            Ok(None)
        } else {
            Ok(Some(standards))
        }
    }
}