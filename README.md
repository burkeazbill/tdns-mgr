# bash Technitium DNS Manager

**Version**: 1.0.0  
**Author**: Burke Azbill  
**API Reference**: [Technitium DNS Server API](https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md)

---

## Overview

`tdns-mgr.sh` is a comprehensive command-line client for managing Technitium DNS Server via its REST API. It provides full functionality for DNS zone management, record manipulation, and server administration.

### Features

- ✅ **Complete API Implementation** - Full coverage of Technitium DNS Server API
- ✅ **Authentication Management** - Secure token-based authentication
- ✅ **Zone Management** - Create, delete, enable/disable, import, and export DNS zones
- ✅ **Record Management** - Add, update, import, delete DNS records (A, AAAA, CNAME, MX, TXT, NS, PTR, SRV, CAA)
- ✅ **Server Administration** - Statistics, cache management, queries
- ✅ **Interactive Menu** - User-friendly menu when run without arguments
- ✅ **Configuration Storage** - Persistent configuration in `~/.tdns-mgr.conf`
- ✅ **Technitium DNS Server Version** - Script developed and tested against Technitium DNS Server Version 14.3
- ✅ **Error Handling** - Comprehensive error checking and reporting

---

## Installation

### Prerequisites

- `bash` (4.0+)
- `curl`
- `jq`
- `awk`

The script checks for these dependencies on execution and can attempt to install them automatically on supported systems (Debian/Ubuntu, RHEL/CentOS, Alpine, Arch, OpenSUSE, MacOS via Homebrew).

### Manual Installation

```bash
# Copy script to PATH
sudo cp tdns-mgr.sh /usr/local/bin/tdns-mgr
sudo chmod +x /usr/local/bin/tdns-mgr

# Verify installation
tdns-mgr --version
```

---

## Quick Start

### 1. Configure Server Connection

```bash
# Set DNS server address
tdns-mgr config set server dns.example.com

# Set port (default: 5380)
tdns-mgr config set port 5380

# Set username (default: admin)
tdns-mgr config set user admin

# View current configuration
tdns-mgr config show
```

### 2. Login

```bash
# Interactive login (prompts for password)
tdns-mgr login

# Non-interactive login
DNS_PASS="yourpassword" tdns-mgr login
```

### 3. Basic Operations

```bash
# List all zones
tdns-mgr list-zones

# Create a zone
tdns-mgr create-zone example.com Primary

# Add an A record
tdns-mgr add-record example.com www A 192.168.1.100

# List records
tdns-mgr list-records example.com
```

---

## Configuration

### Configuration File

Location: `~/.tdns-mgr.conf`

```bash
DNS_SERVER="localhost"
DNS_PORT="5380"
DNS_TOKEN="your-auth-token-here"
DNS_USER="admin"
```

### Environment Variables

You can override configuration using environment variables:

```bash
export DNS_SERVER="dns.example.com"
export DNS_PORT="5380"
export DNS_USER="admin"
export DNS_PASS="password"  # For non-interactive login
export DNS_TOKEN="token"     # Skip login if token is set
```

---

## Global Options
    
The script supports the following global options (must be specified before the command):

- `-q`, `--quiet`, `--silent`: Suppress all informational output (banners, success/info messages). Only JSON output and critical errors will be displayed.
- `-h`, `--help`: Show help menu.
- `-v`, `--version`: Show version.

---

## Commands Reference

### Authentication Commands

#### login

Login to the DNS server and obtain an authentication token.

```bash
tdns-mgr login

# Non-interactive
DNS_PASS="password" tdns-mgr login
```

**Response**: Saves authentication token to configuration file.

---

#### logout

Logout from the DNS server and clear the authentication token.

```bash
tdns-mgr logout
```

---

#### change-password

Change the password for the current user.

```bash
tdns-mgr change-password newpassword

# Interactive (prompts for password)
tdns-mgr change-password
```

---

#### config

Manage configuration settings.

```bash
# Show current configuration
tdns-mgr config show

# Set server address
tdns-mgr config set server dns.example.com

# Set port
tdns-mgr config set port 5380

# Set username
tdns-mgr config set user admin
```

---

### Zone Management Commands

#### list-zones

List all DNS zones on the server.

```bash
tdns-mgr list-zones
```

**Output**: JSON array of zones with details.

---

#### create-zone

Create a new DNS zone.

```bash
tdns-mgr create-zone <domain> [type]
```

**Parameters**:
- `domain`: Domain name (e.g., example.com)
- `type`: Zone type (default: Primary)
  - `Primary`: Primary zone (master)
  - `Secondary`: Secondary zone (slave)
  - `Stub`: Stub zone
  - `Forwarder`: Conditional forwarder

**Examples**:

```bash
# Create primary zone
tdns-mgr create-zone example.com Primary

# Create secondary zone
tdns-mgr create-zone backup.com Secondary

# Create forwarder zone
tdns-mgr create-zone internal.local Forwarder
```

---

#### delete-zone

Delete a DNS zone.

```bash
tdns-mgr delete-zone <domain>
```

**Example**:

```bash
tdns-mgr delete-zone example.com
```

**Note**: Prompts for confirmation before deletion.

---

#### enable-zone

Enable a disabled DNS zone.

```bash
tdns-mgr enable-zone <domain>
```

**Example**:

```bash
tdns-mgr enable-zone example.com
```

---

#### disable-zone

Disable a DNS zone without deleting it.

```bash
tdns-mgr disable-zone <domain>
```

**Example**:

```bash
tdns-mgr disable-zone example.com
```

---

### Export & Import Commands

- `tdns-mgr export-zone <domain> [file]`: Export a single zone to a BIND Zone File (RFC 1035). If file is omitted, defaults to `<domain>.txt`.
- `tdns-mgr import-zone <domain> <file>`: Import a single zone from a BIND Zone File.
- `tdns-mgr export-zones [file]`: Export ALL zones to a server backup zip file. If file is omitted, defaults to `dns-zones-export-<timestamp>.zip`.
- `tdns-mgr import-zones <file>`: Import ALL zones from a backup zip file. **WARNING**: This may overwrite existing zones.

---

### Record Management Commands

#### list-records

List all DNS records in a zone.

```bash
tdns-mgr list-records <zone>
```

**Example**:

```bash
tdns-mgr list-records example.com
```

**Output**: JSON array of all records in the zone.

---

#### add-record

Add a DNS record to a zone.

```bash
tdns-mgr add-record <zone> <name> <type> <value> [ttl] [--ptr]
```

**Parameters**:
- `zone`: Zone name (e.g., example.com)
- `name`: Record name (e.g., www, mail, @)
- `type`: Record type (A, AAAA, CNAME, MX, TXT, NS, PTR, SRV, CAA)
- `value`: Record value
- `ttl`: Time to live in seconds (default: 3600)
- `--ptr`: (Optional) Automatically create reverse PTR record and zone (only for A/AAAA records)

**Examples**:

```bash
# Add A record with automatic PTR creation
tdns-mgr add-record example.com www A 192.168.1.100 --ptr

# Add A record with custom TTL
tdns-mgr add-record example.com www A 192.168.1.100 7200

# Add AAAA record (IPv6)
tdns-mgr add-record example.com www AAAA 2001:db8::1

# Add CNAME record
tdns-mgr add-record example.com mail CNAME mail.example.com

# Add MX record (priority 10)
tdns-mgr add-record example.com @ MX mail.example.com 10

# Add TXT record
tdns-mgr add-record example.com @ TXT "v=spf1 include:_spf.example.com ~all"

# Add NS record
tdns-mgr add-record example.com @ NS ns1.example.com

# Add PTR record (reverse DNS)
tdns-mgr add-record 1.168.192.in-addr.arpa 100 PTR server.example.com
```

---

#### update-record

Update an existing DNS record.

```bash
tdns-mgr update-record <zone> <name> <type> <old_value> <new_value> [ttl]
```

**Example**:

```bash
# Update A record
tdns-mgr update-record example.com www A 192.168.1.100 192.168.1.101

# Update with custom TTL
tdns-mgr update-record example.com www A 192.168.1.100 192.168.1.101 7200
```

---

#### delete-record

Delete a DNS record from a zone.

```bash
tdns-mgr delete-record <zone> <name> <type> [value]
```

**Parameters**:
- `zone`: Zone name
- `name`: Record name
- `type`: Record type
- `value`: Record value (optional, for specific record deletion)

**Examples**:

```bash
# Delete specific A record
tdns-mgr delete-record example.com www A 192.168.1.100

# Delete all A records for name
tdns-mgr delete-record example.com www A

# Delete CNAME record
tdns-mgr delete-record example.com mail CNAME
```

---

#### import-records

Import DNS records from a CSV file.

```bash
tdns-mgr import-records <file> [--ptr]
```

**Parameters**:
- `file`: Path to CSV file
- `--ptr`: (Optional) Automatically create reverse PTR record and zone for A/AAAA records

**CSV Format**:
- Header required: `zone,name,type,value`
- Comments allowed (start line with `#`)
- Columns:
  - `zone`: Target zone
  - `name`: Record name (e.g., `www`, `@`)
  - `type`: Record type
  - `value`: Record value (IP, CNAME target, text, etc.)

**Example CSV**:
```csv
zone,name,type,value
# Web server
example.com,www,A,192.168.1.100
# Mail
example.com,mail,CNAME,example.com
```

Example file: [new-dns-records.csv](new-dns-records.csv)

**Output**: JSON object with results.
```json
{
  "New Records": 2,
  "Errors": 0,
  "Message": "Success"
}
```

---

### Server Management Commands

#### server-status

Check if the DNS server is accessible.

```bash
tdns-mgr server-status
```

**Output**: Success or error message indicating server accessibility.

---

#### server-stats

Get DNS server statistics.

```bash
tdns-mgr server-stats
```

**Output**: JSON object with server statistics including:
- Total queries
- Total blocked
- Total clients
- Zones count
- Cache entries
- And more...

---

#### flush-cache

Flush the DNS server cache.

```bash
tdns-mgr flush-cache
```

**Use Case**: Clear cached DNS records after making changes.

---

#### query

Query DNS records through the DNS server.

```bash
tdns-mgr query <domain> [type]
```

**Parameters**:
- `domain`: Domain name to query
- `type`: Record type (default: A)

**Examples**:

```bash
# Query A record
tdns-mgr query www.example.com A

# Query MX records
tdns-mgr query example.com MX

# Query TXT records
tdns-mgr query example.com TXT

# Query NS records
tdns-mgr query example.com NS
```

---

## Usage Examples

### Example 1: Setup New Domain

```bash
#!/bin/bash
# Setup a new domain with basic records

DOMAIN="example.com"
IP="192.168.1.100"

# Login (not required if config file already has all details specified)
tdns-mgr login

# Create zone
tdns-mgr create-zone $DOMAIN Primary

# Add A records
tdns-mgr add-record $DOMAIN @ A $IP
tdns-mgr add-record $DOMAIN www A $IP
tdns-mgr add-record $DOMAIN mail A $IP

# Add MX record
tdns-mgr add-record $DOMAIN @ MX mail.$DOMAIN 10

# Add TXT record for SPF
tdns-mgr add-record $DOMAIN @ TXT "v=spf1 mx ~all"

# Add CNAME records
tdns-mgr add-record $DOMAIN ftp CNAME www.$DOMAIN
tdns-mgr add-record $DOMAIN webmail CNAME mail.$DOMAIN

# List all records
tdns-mgr list-records $DOMAIN

echo "Domain $DOMAIN configured successfully!"
```

---

### Example 2: Bulk Add A Records

```bash
#!/bin/bash
# Add multiple A records from a file

ZONE="example.com"

# File format: hostname ip_address
# www 192.168.1.100
# mail 192.168.1.101
# ftp 192.168.1.102

while read hostname ip; do
    echo "Adding: $hostname.$ZONE -> $ip"
    tdns-mgr add-record $ZONE $hostname A $ip
done < hosts.txt
```

---

### Example 3: Backup DNS Records

```bash
#!/bin/bash
# Backup all DNS records from a zone

ZONE="example.com"
BACKUP_FILE="dns-backup-${ZONE}-$(date +%Y%m%d).json"

tdns-mgr list-records $ZONE > $BACKUP_FILE

echo "Backup saved to: $BACKUP_FILE"
```

---

### Example 4: Monitor DNS Server

```bash
#!/bin/bash
# Monitor DNS server statistics

while true; do
    clear
    echo "=== DNS Server Statistics ==="
    echo "Time: $(date)"
    echo ""
    tdns-mgr server-stats | jq '.response.stats | {
        totalQueries,
        totalBlocked,
        totalClients,
        zones,
        cachedEntries
    }'
    sleep 5
done
```

---

### Example 5: Update Multiple Records

```bash
#!/bin/bash
# Update IP address for multiple records

ZONE="example.com"
OLD_IP="192.168.1.100"
NEW_IP="192.168.1.200"

RECORDS=("www" "mail" "ftp")

for record in "${RECORDS[@]}"; do
    echo "Updating: $record.$ZONE"
    tdns-mgr update-record $ZONE $record A $OLD_IP $NEW_IP
done

echo "All records updated!"
```

### Example 6: Export and Import

```bash
# Export a single zone (BIND format)
tdns-mgr export-zone example.com example.com.db

# Import a single zone
tdns-mgr import-zone example.com example.com.db

# Export ALL zones
tdns-mgr export-zones all-zones.zip

# Import ALL zones from backup
tdns-mgr import-zones all-zones.zip
```

### Example 7: Quiet Mode for Scripting

```bash
#!/bin/bash
# Using quiet mode to get raw JSON output without banners

# Get stats quietly and parse with jq
TOTAL_QUERIES=$(tdns-mgr --quiet server-stats | jq '.response.stats.totalQueries')
echo "Total Queries: $TOTAL_QUERIES"

# Verify functionality
if tdns-mgr -q check-auth 2>/dev/null; then
    echo "Authenticated"
fi
```
    
---

## Integration Examples

### Python Integration

```python
#!/usr/bin/env python3
import subprocess
import json

def dns_manager(command):
    """Execute tdns-mgr command and return JSON output"""
    result = subprocess.run(
        ['tdns-mgr'] + command.split(),
        capture_output=True,
        text=True
    )
    try:
        return json.loads(result.stdout)
    except:
        return result.stdout

# List zones
zones = dns_manager('list-zones')
print(f"Total zones: {len(zones.get('response', {}).get('zones', []))}")

# Add record
dns_manager('add-record example.com test A 192.168.1.50')
print("Record added")

# Query
result = dns_manager('query www.example.com A')
print(result)
```

---

### Ansible Integration

```yaml
---
- name: Manage DNS records with tdns-mgr
  hosts: localhost
  tasks:
    - name: Create DNS zone
      command: tdns-mgr create-zone example.com Primary
      
    - name: Add A record
      command: >
        tdns-mgr add-record example.com 
        {{ item.name }} A {{ item.ip }}
      loop:
        - { name: 'www', ip: '192.168.1.100' }
        - { name: 'mail', ip: '192.168.1.101' }
        - { name: 'ftp', ip: '192.168.1.102' }
      
    - name: List all records
      command: tdns-mgr list-records example.com
      register: dns_records
      
    - name: Display records
      debug:
        var: dns_records.stdout
```

---

## Troubleshooting

### Connection Issues

```bash
# Check if server is running
tdns-mgr server-status

# Test direct connection
curl http://localhost:5380

# Check configuration
tdns-mgr config show
```

### Authentication Issues

```bash
# Clear token and re-login
tdns-mgr logout
tdns-mgr login

# Check token
cat ~/.tdns-mgr.conf
```

### Permission Issues

```bash
# Ensure config file has correct permissions
chmod 600 ~/.tdns-mgr.conf

# Check if user has API access
tdns-mgr server-stats
```

### API Errors

Most API errors will return JSON with error details:

```json
{
  "status": "error",
  "errorMessage": "Description of the error"
}
```

Enable verbose output for debugging:

```bash
# Add -v flag to curl calls in script
# Edit tdns-mgr.sh and add -v to curl commands
```

---

## API Reference

This tool implements the Technitium DNS Server API:

**Official Documentation**: https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md

### Implemented Endpoints

#### Authentication
- `/api/user/login` - User login
- `/api/user/logout` - User logout
- `/api/user/changePassword` - Change password

#### Zones
- `/api/zones/list` - List zones
- `/api/zones/create` - Create zone
- `/api/zones/delete` - Delete zone
- `/api/zones/enable` - Enable zone
- `/api/zones/disable` - Disable zone

#### Records
- `/api/zones/records/get` - Get records
- `/api/zones/records/add` - Add record
- `/api/zones/records/update` - Update record
- `/api/zones/records/delete` - Delete record

#### Server
- `/api/dashboard/stats/get` - Get statistics
- `/api/cache/flush` - Flush cache
- `/api/dns/query` - Query DNS

---

## Best Practices

### 1. Security

```bash
# Never commit credentials to version control
echo ".tdns-mgr.conf" >> .gitignore

# Use environment variables for automation
export DNS_PASS="password"
tdns-mgr login

# Clear password after use
unset DNS_PASS
```

### 2. Backup

```bash
# Regular backups
tdns-mgr list-zones > zones-backup.json

# Backup specific zone
tdns-mgr list-records example.com > example.com-backup.json
```

### 3. Testing

```bash
# Test in non-production first
tdns-mgr config set server test-dns.local

# Verify changes
tdns-mgr query www.example.com A
```

### 4. Automation

```bash
# Use scripts for repetitive tasks
# Use error checking
if tdns-mgr add-record example.com test A 192.168.1.1; then
    echo "Success"
else
    echo "Failed"
    exit 1
fi
```

---

## Advanced Usage

### Custom API Calls

For API endpoints not yet implemented, you can extend the script:

```bash
# Add to tdns-mgr.sh
cmd_custom_api() {
    check_auth
    local endpoint="$1"
    local data="$2"
    
    local response=$(api_post "$endpoint" "token=${DNS_TOKEN}&${data}")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}
```

### Batch Operations

```bash
# Process multiple domains
for domain in $(cat domains.txt); do
    tdns-mgr create-zone $domain Primary
    tdns-mgr add-record $domain @ A 192.168.1.100
done
```

---

## Support

For issues or questions:

1. Check the [Technitium DNS Server documentation](https://github.com/TechnitiumSoftware/DnsServer)
2. Review the [API documentation](https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md)
3. Check HoloConsole documentation

---

## License

© HoloConsole Project by Burke Azbill

This tool is provided as part of the HoloConsole project for managing Technitium DNS Server installations.

---

## Changelog

### Version 1.0.0 (2025-10-31)
- Initial release
- Full API implementation
- Authentication management
- Zone management
- Record management (A, AAAA, CNAME, MX, TXT, NS, PTR)
- Server administration
- Interactive menu
- Configuration management
- Colored output
- Comprehensive documentation

