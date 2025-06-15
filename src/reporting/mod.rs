use crate::logging::AuditLog;
use chrono::{DateTime, Utc};
use std::path::PathBuf;
use thiserror::Error;
use std::io::Write;

#[derive(Error, Debug)]
pub enum ReportError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub struct ReportGenerator {
    log_dir: PathBuf,
}

impl ReportGenerator {
    pub fn new(log_dir: PathBuf) -> Self {
        Self { log_dir }
    }

    pub async fn generate_report(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        format: &str,
        output: Option<PathBuf>,
    ) -> Result<(), ReportError> {
        let logs = self.collect_logs(from, to).await?;

        match format {
            "csv" => self.write_csv(&logs, output).await?,
            "json" => self.write_json(&logs, output).await?,
            _ => return Err(ReportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unsupported format",
            ))),
        }

        Ok(())
    }

    async fn collect_logs(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<AuditLog>, ReportError> {
        // Implementation for collecting logs within the date range
        Ok(Vec::new())
    }

    async fn write_csv(
        &self,
        logs: &[AuditLog],
        output: Option<PathBuf>,
    ) -> Result<(), ReportError> {
        let writer: Box<dyn Write> = match output {
            Some(path) => Box::new(std::fs::File::create(path)?),
            None => Box::new(std::io::stdout()),
        };

        let mut wtr = csv::Writer::from_writer(writer);
        for log in logs {
            wtr.serialize(log)?;
        }
        wtr.flush()?;
        Ok(())
    }

    async fn write_json(
        &self,
        logs: &[AuditLog],
        output: Option<PathBuf>,
    ) -> Result<(), ReportError> {
        let writer:Box<dyn Write> = match output {
            Some(path) => Box::new(std::fs::File::create(path)?),
            None => Box::new(std::io::stdout()),
        };

        serde_json::to_writer_pretty(writer, logs)?;
        Ok(())
    }
} 