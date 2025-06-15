use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize the audit configuration
    Init {
        /// Path to the config file
        #[arg(short, long, default_value = "/etc/auditrust/config.yaml")]
        config: PathBuf,
    },
    /// Start the audit monitoring
    Run {
        /// Path to the config file
        #[arg(short, long, default_value = "/etc/auditrust/config.yaml")]
        config: PathBuf,
    },
    /// Check the current status of the audit monitoring
    Status,
    /// Generate audit reports
    Report {
        /// Start date (YYYY-MM-DD)
        #[arg(short='s', long)]
        from: String,
        /// End date (YYYY-MM-DD)
        #[arg(short='e', long)]
        to: String,
        /// Output format (csv or json)
        #[arg(short='f', long, default_value = "json")]
        format: String,
        /// Output file path
        #[arg(short='o', long)]
        output: Option<PathBuf>,
    },
} 