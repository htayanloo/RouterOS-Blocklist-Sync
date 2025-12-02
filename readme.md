# RouterOS Blocklist Sync

A Go-based security automation tool that automatically blocks attacker IPs on MikroTik routers based on honeypot/Splunk logs. Features progressive escalation policies and intelligent state tracking to identify and permanently block persistent attackers.

## Overview

This tool reads a CSV file containing attacker IP addresses (typically exported from Splunk or honeypot logs) and automatically adds them to MikroTik firewall address lists. It implements a smart escalation mechanism where repeat offenders receive progressively longer blocking periods, culminating in permanent blocks.

### Key Features

- **Automatic IP Blocking**: Seamlessly integrates with MikroTik routers via API
- **Progressive Escalation**: Repeat attackers get longer timeouts (1h → 3h → 7h → permanent)
- **State Persistence**: Tracks attack history across runs to identify repeat offenders
- **Whitelist Support**: Protect legitimate IPs and networks from being blocked
- **Dual-List Strategy**: Separate temporary and permanent block lists
- **Auto-Setup**: Interactive setup creates necessary directories and default configuration
- **Cron-Friendly**: Designed for automated periodic execution

## How It Works

```
CSV Input → IP Extraction → Whitelist Check → State Tracking → Escalation Policy → MikroTik API
```

1. **CSV Parsing**: Reads attacker IPs from CSV file (skips header row)
2. **Whitelist Validation**: Checks if IP is in whitelist (supports CIDR notation)
3. **State Tracking**: Increments offense counter for each IP
4. **Escalation Logic**:
   - 1st offense: 1 hour timeout
   - 2nd offense: 3 hours timeout
   - 3rd offense: 7 hours timeout
   - 4th+ offense: Permanent block
5. **MikroTik Blocking**: Adds IP to appropriate address list with calculated timeout

## Installation

### Prerequisites

- Go 1.24 or later
- MikroTik router with API access enabled
- Read access to Splunk/honeypot CSV exports

### Build from Source

```bash
git clone <repository-url>
cd routeros-blocklist-sync
go mod download
go build -o blocker main.go
```

### Initial Setup

The tool will automatically guide you through setup on first run:

```bash
sudo ./blocker /path/to/attackers.csv
```

This will:
1. Prompt to create `/opt/htb_blocker` directory
2. Generate default `config.env` file
3. Create necessary state files

## Configuration

Edit `/opt/htb_blocker/config.env` to configure the tool:

```bash
# MikroTik settings
MT_HOST=192.168.88.1:8728          # MikroTik router IP:port (default API port is 8728)
MT_USER=admin                       # MikroTik username with API access
MT_PASS=yourpassword                # MikroTik password

# Lists
LIST_TEMP=blocked_attackers         # Temporary block list name
LIST_PERM=blocked_permanent         # Permanent block list name

# Whitelist (comma separated)
WHITELIST=8.8.8.8,192.168.1.0/24    # IPs/networks to never block

# State file
STATE_FILE=/opt/htb_blocker/state.json

# Escalation (hours)
ESCALATE_1=1                        # First offense timeout
ESCALATE_2=3                        # Second offense timeout
ESCALATE_3=7                        # Third offense timeout
```

### MikroTik Router Setup

1. **Enable API Access**:
   ```
   /ip service enable api
   /ip service set api address=192.168.88.0/24  # Restrict to management network
   ```

2. **Create Address Lists** (optional - will be created automatically):
   ```
   /ip firewall address-list add list=blocked_attackers
   /ip firewall address-list add list=blocked_permanent
   ```

3. **Create Firewall Rules**:
   ```
   /ip firewall filter add chain=input action=drop src-address-list=blocked_attackers comment="Block temporary attackers"
   /ip firewall filter add chain=input action=drop src-address-list=blocked_permanent comment="Block permanent attackers"
   ```

## Usage

### Manual Execution

```bash
./blocker /path/to/attackers.csv
```

### CSV Format

The tool expects a CSV file with IP addresses. Example format:

```csv
src_ip
192.0.2.100
198.51.100.50
203.0.113.25
```

**Note**: The first line is treated as a header and skipped.

### Automated Execution (Cron)

Add to crontab for periodic blocking (every 5 minutes):

```bash
*/5 * * * * echo "---- $(date) ----" >> /opt/htb_blocker/blocker.log && /opt/htb_blocker/blocker /opt/splunk/.../attackers.csv >> /opt/htb_blocker/blocker.log 2>&1
```

### Log Output

The tool provides emoji-coded status messages:

```
⚪ 192.168.1.100 → SKIP           # Whitelisted IP
🛡️ 203.0.113.25 → attempt 1 → timeout 01:00:00    # First offense
🛡️ 198.51.100.50 → attempt 2 → timeout 03:00:00   # Second offense
🚫 192.0.2.100 → Permanent block  # Fourth+ offense
❌ Block failed for X.X.X.X: error message         # Error occurred
```

## State File

The tool maintains state in `/opt/htb_blocker/state.json`:

```json
{
  "192.0.2.100": 4,
  "198.51.100.50": 2,
  "203.0.113.25": 1
}
```

This tracks how many times each IP has been seen, enabling the escalation mechanism.

## Integration with Splunk

### Typical Workflow

1. **Splunk Search**: Create search to identify attackers
   ```spl
   index=honeypot action=attack
   | stats count by src_ip
   | where count > 5
   | table src_ip
   ```

2. **Export to CSV**: Schedule report to export results to CSV

3. **Cron Job**: Run blocker periodically against exported CSV

4. **MikroTik**: Automatically blocks identified attackers

## Security Considerations

- **API Credentials**: Store config.env with restricted permissions (chmod 600)
- **Whitelist**: Always include your management networks to prevent lockout
- **Testing**: Test with non-critical IPs before production deployment
- **API Access**: Restrict MikroTik API to management network only
- **False Positives**: Review logs regularly to ensure legitimate traffic isn't blocked

## Troubleshooting

### Connection Issues

```
Mikrotik error: dial tcp: connection refused
```

**Solution**: Verify API is enabled and accessible:
```
/ip service print
ping <MT_HOST>
```

### Authentication Failures

```
Mikrotik error: authentication failed
```

**Solution**: Verify credentials in config.env and user has API permissions

### Whitelist Not Working

- Ensure CIDR notation is correct (e.g., `192.168.1.0/24`)
- Check for extra spaces in config.env
- Verify IP parsing with manual test

## Project Structure

```
.
├── main.go           # Main application code
├── go.mod            # Go module dependencies
├── go.sum            # Dependency checksums
└── README.md         # This file

/opt/htb_blocker/
├── config.env        # Configuration file
├── state.json        # Attack state tracking
└── blocker.log       # Execution logs (if using cron)
```

## Dependencies

- [go-routeros](https://github.com/go-routeros/routeros) - MikroTik RouterOS API client

## License

This is a security automation tool. Use responsibly and ensure you have proper authorization to block traffic on your network.

## Contributing

Contributions are welcome! Areas for improvement:

- Support for IPv6 addresses
- Database backend for state tracking
- Web dashboard for monitoring
- Multi-router support
- Email/webhook notifications
- Custom escalation policies per IP range

## Author

Created for automated threat response in honeypot and security monitoring environments.
