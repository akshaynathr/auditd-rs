use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditConfig {
    pub rules: Vec<AuditRule>,
    pub log_dir: PathBuf,
    pub rotation: LogRotation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditRule {
    pub file: Option<String>,
    pub process_name: Option<String>,
    pub user: Option<String>,
    pub events: Vec<AuditEvent>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum AuditEvent {
    Open,
    Write,
    Delete,
    Execute,
    Connect,
    DnsQuery,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogRotation {
    pub max_size: usize,
    pub max_files: usize,
    pub compress: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            rules: vec![
                AuditRule {
                    file: Some("/etc/passwd".to_string()),
                    process_name: None,
                    user: None,
                    events: vec![AuditEvent::Open, AuditEvent::Write],
                },
                AuditRule {
                    file: Some("/var/log/".to_string()),
                    process_name: None,
                    user: None,
                    events: vec![AuditEvent::Open, AuditEvent::Write, AuditEvent::Delete],
                },
            ],
            log_dir: PathBuf::from("/var/log/auditrust"),
            rotation: LogRotation {
                max_size: 100 * 1024 * 1024, // 100MB
                max_files: 7,
                compress: true,
            },
        }
    }
} 