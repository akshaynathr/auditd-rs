use aya::{
    include_bytes_aligned,
    programs::{TracePoint,},
    Ebpf,
};
use aya::programs::trace_point::TracePointLinkId;
use aya_log::EbpfLogger;
use std::sync::Arc;
use tokio::sync::Mutex;
use thiserror::Error;
use aya::programs::ProgramError;

#[derive(thiserror::Error, Debug)]
pub enum EbpfError {
    #[error("BPF error: {0}")]
    Ebpf(#[from] aya::EbpfError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Program error: {0}")]
    Program(#[from] ProgramError),

    #[error("Program '{0}' not found in BPF object")]
    ProgramNotFound(String),

    #[error("Failed to initialize eBPF logger: {0}")]
    LoggerInit(String),
}

pub struct EbpfManager {
    bpf: Arc<Mutex<Ebpf>>,
    links: Vec<TracePointLinkId>,
}

impl EbpfManager {
    pub async fn new() -> Result<Self, EbpfError> {
        let mut bpf = Ebpf::load(include_bytes_aligned!(
            "../../ebpf/trace.o"
        ))?;
        // let bpf_lock = Arc::new(Mutex::new(bpf));
        // let mut bpf = bpf_lock.lock().await;
        //EbpfLogger::init(&mut bpf).map_err(|e| EbpfError::LoggerInit(e.to_string()))?;
        println!("eBPF object loaded successfully");
        Ok(Self {
            bpf: Arc::new(Mutex::new(bpf)),
            links: Vec::new(),
        })
    }

    pub async fn attach_probes(&mut self) -> Result<(), EbpfError> {
        let mut bpf = self.bpf.lock().await;

        // Attach to execve
        println!("Attaching to execve probe...");
        let execve_program: &mut TracePoint = bpf
            .program_mut("trace_execve_enter")
            .ok_or_else(|| EbpfError::ProgramNotFound("execve".to_string()))?
            .try_into()?;
        let link = execve_program.attach("sys_enter", "execve")?;
        self.links.push(link);
        println!("execve probe attached successfully");
        // Attach to file operations
        let file_program: &mut TracePoint = bpf
            .program_mut("file_ops")
            .ok_or_else(|| EbpfError::ProgramNotFound("file_ops".to_string()))?
            .try_into()?;
        let link = file_program.attach("sys_enter", "open")?;
        self.links.push(link);

        // Attach to network operations
        let net_program: &mut TracePoint = bpf
            .program_mut("net_ops")
            .ok_or_else(|| EbpfError::ProgramNotFound("net_ops".to_string()))?
            .try_into()?;
        let link = net_program.attach("sys_enter", "connect")?;
        self.links.push(link);

        Ok(())
    }

    pub async fn detach_probes(&mut self) {
        self.links.clear();
    }
} 