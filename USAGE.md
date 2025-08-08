# Arwah Usage Guide

Arwah is a unified network security tool that combines port scanning (RustScan) and packet analysis (Sniffglue) functionality.

## Basic Usage

```bash
arwah [MODE FLAGS] [OPTIONS]
```

## Mode Flags

### Scanning Mode
- `--scan` or `-s`: Enable port scanning mode (RustScan functionality)
- This is the **default mode** if no mode flags are specified

### Sniffing Mode  
- `--sniff` or `-n`: Enable packet sniffing mode (Sniffglue functionality)

### Combined Mode
- Use both `--scan --sniff` to run scanning followed by packet sniffing

## Examples

### Port Scanning (Default Mode)
```bash
# Basic port scan
arwah -a 192.168.1.1 -p 80,443

# Scan with custom settings
arwah -a 192.168.1.0/24 -r 1-1000 --batch-size 1000

# Explicit scanning mode
arwah --scan -a target.com -p 1-65535 --greppable
```

### Packet Sniffing (Requires root privileges)
```bash
# Basic packet sniffing
sudo arwah --sniff

# Sniff specific interface (will use default settings)
sudo arwah --sniff
```

### Combined Mode
```bash
# Scan then sniff
sudo arwah --scan --sniff -a 192.168.1.1 -p 80,443

# Quick scan and monitor traffic
sudo arwah -s -n -a target.com -p 80,443,8080
```

## Scanning Options (RustScan)

- `-a, --addresses`: Target IP addresses or hostnames
- `-p, --ports`: Specific ports to scan
- `-r, --range`: Port range (e.g., 1-1000)
- `-b, --batch-size`: Batch size for scanning (default: 4500)
- `-t, --timeout`: Timeout in milliseconds (default: 1500)
- `--tries`: Number of tries (default: 1)
- `-u, --ulimit`: Set ulimit
- `--scan-order`: Scan order (serial/random)
- `--scripts`: Script execution (none/default/custom)
- `--udp`: UDP scan
- `-g, --greppable`: Greppable output
- `--no-banner`: Disable banner
- `-e, --exclude-ports`: Exclude specific ports
- `-x, --exclude-addresses`: Exclude specific addresses

## Sniffing Options (Sniffglue)

When using `--sniff` mode, arwah uses default sniffing settings:
- Interface: Default network interface
- Threads: Number of CPU cores
- Verbosity: Level 1
- Format: Compact output
- No promiscuous mode
- No file reading

## Notes

1. **Root Privileges**: Packet sniffing requires root/administrator privileges
2. **Default Behavior**: If no mode flags are specified, arwah defaults to scanning mode
3. **Combined Usage**: Both modes can run sequentially with `--scan --sniff`
4. **Original Features**: All original RustScan and Sniffglue features are preserved

## Quick Reference

| Command | Description |
|---------|-------------|
| `arwah -a IP` | Default scan mode |
| `arwah --scan -a IP` | Explicit scan mode |
| `sudo arwah --sniff` | Sniff mode only |
| `sudo arwah -s -n -a IP` | Combined mode |

## Help

```bash
arwah --help
```

For detailed options and examples.