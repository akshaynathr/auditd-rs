# Auditd-rs alpha 0.1
A developer-friendly eBPF-based audit reporting tool designed to help DevOps and security engineers collect and export audit logs for compliance (e.g., SOC2, ISO 27001).

## Features

- Process execution monitoring (execve, fork)
- File access monitoring (open/write/delete)
- Network activity monitoring (connect syscall)
- Configurable audit rules via YAML
- Structured JSON logging
- Exportable reports in CSV and JSON formats

## Requirements

- Ubuntu 20.04 or later
- Linux kernel 5.4 or later
- Rust toolchain
- BPF Compiler Collection (BCC)
- libbpf development files

## Installation

1. Install system dependencies:
```bash
sudo apt-get update
sudo apt-get install -y build-essential libbpf-dev clang llvm libelf-dev
```

2. Install Rust:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

3. Clone and build the project:
```bash
git clone https://github.com/yourusername/auditrust.git
cd auditrust
cargo build --release
```

## Usage

1. Initialize the configuration:
```bash
sudo ./target/release/auditrust init
```

2. Start monitoring:
```bash
sudo ./target/release/auditrust run
```

3. Generate a report:
```bash
./target/release/auditrust report --from 2024-03-01 --to 2024-03-03 --format json
```

## Configuration

The tool uses a YAML configuration file (default: `/etc/auditrust/config.yaml`). Here's a sample configuration:

```yaml
rules:
  - file: /etc/passwd
    events: [open, write]
  - process_name: python
    user: root
    events: [execute, connect]

log_dir: /var/log/auditrust
rotation:
  max_size: 104857600  # 100MB
  max_files: 7
  compress: true
```

## Security Considerations

- The tool requires root privileges to attach eBPF programs
- Log files should be properly secured with appropriate permissions
- Consider encrypting sensitive log data
- Regular log rotation and archival is recommended

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 