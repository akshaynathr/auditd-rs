use chrono::{DateTime, Utc};
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::fs;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LogError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditLog {
    pub timestamp: DateTime<Utc>,
    pub user: String,
    pub process_name: String,
    pub process_id: u32,
    pub event_type: String,
    pub file_path: Option<String>,
    pub network_dest: Option<String>,
    pub syscall: String,
    pub success: bool,
}

pub struct LogManager {
    log_dir: PathBuf,
    current_log: PathBuf,
    max_size: usize,
    max_files: usize,
}

impl LogManager {
    pub fn new(log_dir: PathBuf) -> Result<Self, LogError> {
        fs::create_dir_all(&log_dir)?;
        let current_log = log_dir.join(format!(
            "audit-{}.json",
            chrono::Utc::now().format("%Y-%m-%d")
        ));
        Ok(Self {
            log_dir,
            current_log,
            max_size: 100 * 1024 * 1024, // 100MB default
            max_files: 7,
        })
    }

    pub fn write_log(&self, log: &AuditLog) -> Result<(), LogError> {
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.current_log)?;

        serde_json::to_writer(file, log)?;
        Ok(())
    }

    pub fn rotate_logs(&self) -> Result<(), LogError> {
        if !self.current_log.exists() {
            return Ok(());
        }

        let metadata = fs::metadata(&self.current_log)?;
        if metadata.len() < self.max_size as u64 {
            return Ok(());
        }

        // Rotate old logs
        for i in (1..self.max_files).rev() {
            let old_path = self.log_dir.join(format!("audit-{}.json.{}", 
                chrono::Utc::now().format("%Y-%m-%d"), i));
            let new_path = self.log_dir.join(format!("audit-{}.json.{}", 
                chrono::Utc::now().format("%Y-%m-%d"), i + 1));
            
            if old_path.exists() {
                fs::rename(old_path, new_path)?;
            }
        }

        // Rename current log
        let rotated_path = self.log_dir.join(format!("audit-{}.json.1", 
            chrono::Utc::now().format("%Y-%m-%d")));
        fs::rename(&self.current_log, rotated_path)?;

        // Create new log file
        let _ = fs::File::create(&self.current_log)?;
        
        info!("Rotated log files");
        Ok(())
    }

    pub fn set_max_size(&mut self, size: usize) {
        self.max_size = size;
    }

    pub fn set_max_files(&mut self, count: usize) {
        self.max_files = count;
    }
} 