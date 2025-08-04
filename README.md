# Arwah - Unified Network Security Tool

Arwah is a powerful, unified network security tool that combines the functionality of RustScan (port scanning) and Sniffglue (packet analysis) into a single, efficient Rust application.

## Features

### 🚀 Port Scanning (RustScan Integration)
- **Ultra-fast port scanning** with customizable batch sizes
- **Multi-threaded scanning** for maximum performance  
- **Script integration** for automated vulnerability assessment
- **Flexible target specification** (IPs, ranges, hostnames)
- **Greppable output** for easy integration with other tools

### 📡 Packet Analysis (Sniffglue Integration)  
- **Real-time packet capture** and analysis
- **Multi-protocol support** (TCP, UDP, HTTP, TLS, DNS, DHCP, etc.)
- **Multiple output formats** (compact, debugging, JSON)
- **Multi-threaded packet processing**
- **PCAP file analysis** support

### 🔧 Unified Interface
- **Single binary** for both scanning and sniffing
- **Flexible command structure** with subcommands
- **Combined mode** for comprehensive network analysis
- **Consistent configuration** across all features

## Quick Start

### Installation

```bash
# Build from source
git clone https://github.com/your-org/arwah.git
cd arwah
cargo build --release

# The binary will be available at target/release/arwah
```

### Basic Usage

```bash
# Port scanning
arwah scan -a 192.168.1.1

# Packet sniffing  
arwah sniff

# Combined mode (scan then sniff)
arwah --both

# Help for specific modes
arwah scan --help
arwah sniff --help
```

## Usage Modes

### 1. Port Scanning Mode

```bash
# Scan a single IP
arwah scan -a 192.168.1.1

# Scan multiple IPs
arwah scan -a 192.168.1.1,192.168.1.2,192.168.1.3

# Scan a subnet
arwah scan -a 192.168.1.0/24

# Scan specific ports
arwah scan -a 192.168.1.1 -p 22,80,443

# Scan port range
arwah scan -a 192.168.1.1 -p 1-1000

# Fast scan with custom batch size
arwah scan -a 192.168.1.1 -b 5000 -t 1000

# Run with scripts
arwah scan -a 192.168.1.1 -s default
```

### 2. Packet Sniffing Mode

```bash
# Listen on default interface
arwah sniff

# Listen on specific interface
arwah sniff -i eth0

# Read from pcap file
arwah sniff -r capture.pcap

# JSON output for automation
arwah sniff --json

# Verbose debugging output
arwah sniff --debugging -v 4

# Multi-threaded processing
arwah sniff --threads 8
```

### 3. Combined Mode

```bash
# Run both scan and sniff sequentially
arwah --both

# This will:
# 1. Perform port scan with default settings
# 2. Start packet capture after scan completes
```

## Configuration

Create a configuration file at `~/.config/arwah/config.toml`:

```toml
[scan]
batch_size = 3000
timeout = 3000
greppable = false

[sniff]
verbose = 2
threads = 4
json = false

[security]
disable_seccomp = false
```

See `arwah.example.toml` for a complete configuration example.

## Output Formats

### Scanning Output
```bash
# Standard format
192.168.1.1 -> [22,80,443]

# Greppable format (--greppable)
192.168.1.1:22
192.168.1.1:80  
192.168.1.1:443
```

### Sniffing Output
```bash
# Compact format (default)
[tcp/SA] 192.168.1.100:54321 -> 93.184.216.34:80 [http] GET / HTTP/1.1

# JSON format (--json)
{"timestamp":"2024-01-01T12:00:00Z","protocol":"tcp","src":"192.168.1.100:54321","dst":"93.184.216.34:80","data":"..."}

# Debug format (--debugging)  
IPv4: Ipv4Header { ... }
  TCP: TcpHeader { ... }
    HTTP: GET / HTTP/1.1 ...
```

## Advanced Features

### Script Integration
```bash
# Run Nmap scripts after port discovery
arwah scan -a target.com -s default

# Custom script execution
arwah scan -a target.com -s custom --command "nmap -sV"
```

### Performance Tuning
```bash
# High-speed scanning
arwah scan -a 192.168.1.0/24 -b 10000 --ulimit 10000

# Multi-threaded packet processing
arwah sniff --threads 16 -v 1
```

### Security Features
```bash
# Run in sandbox mode (default)
arwah sniff

# Disable seccomp for compatibility (not recommended)
arwah sniff --insecure-disable-seccomp
```

## Requirements

- **Rust 1.70+** for building
- **Root privileges** for packet capture
- **Linux/macOS/Windows** support
- **libpcap** for packet capture functionality

## Architecture

Arwah is built with a modular architecture:

```
arwah/
├── src/
│   ├── scanner/          # Port scanning engine (RustScan)
│   ├── centrifuge/       # Packet processing (Sniffglue)  
│   ├── network/          # Protocol parsers
│   ├── fmt/              # Output formatting
│   ├── scripts/          # Script integration
│   └── main.rs           # Unified CLI interface
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **RustScan** - Fast port scanning functionality
- **Sniffglue** - Packet analysis and protocol parsing
- **Rust Community** - For excellent networking and async libraries

## Security Notice

This tool is intended for authorized security testing and network analysis only. Users are responsible for complying with applicable laws and regulations. Unauthorized network scanning or packet capture may be illegal in your jurisdiction.

---

**Abu Ayyub Al Ansar | Abu Ali Al Ansar | Tawheed Network | Free Palestine**