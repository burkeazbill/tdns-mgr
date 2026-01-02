# Technitium DNS Manager - Examples

**Version**: 1.1.0

This document provides comprehensive examples for all `tdns-mgr` commands, organized by category.

---

## Table of Contents

0. [Help System](#help-system)
1. [Authentication](#authentication)
2. [DNS (Zones & Records)](#dns-zones--records)
3. [Cluster Management](#cluster-management)
4. [Administration (Users, Groups, Permissions)](#administration-users-groups-permissions)
5. [DHCP Server Management](#dhcp-server-management)
6. [Apps Management](#apps-management)
7. [Blocked & Allowed Zones](#blocked--allowed-zones)
8. [Logging & Stats](#logging--stats)
9. [DNSSEC Management](#dnssec-management)
10. [Advanced Zone & Server Settings](#advanced-zone--server-settings)
11. [DNS Client](#dns-client)
12. [Automation Examples](#automation-examples)

---

## Help System

The script features a hierarchical help system for easy navigation:

### Summary Help (Default)

Shows available help topics and quick examples:

```bash
# Show summary help
tdns-mgr --help
tdns-mgr -h
tdns-mgr
```

### Topic-Specific Help

Get detailed help for a specific command category:

```bash
# Authentication help
tdns-mgr --help Authentication
tdns-mgr --help auth
tdns-mgr --help login

# DNS help
tdns-mgr --help DNS
tdns-mgr --help zones

# Cluster help
tdns-mgr --help Cluster
tdns-mgr --help clustering

# Administration help
tdns-mgr --help Administration
tdns-mgr --help admin
tdns-mgr --help users

# DHCP help
tdns-mgr --help DHCP

# Apps help
tdns-mgr --help Apps
tdns-mgr --help applications

# Blocked/Allowed zones help
tdns-mgr --help Blocked
tdns-mgr --help blocklist

# Logging and stats help
tdns-mgr --help Logging
tdns-mgr --help logs

# DNSSEC help
tdns-mgr --help DNSSEC

# Settings help
tdns-mgr --help Settings
tdns-mgr --help config

# DNS Client help
tdns-mgr --help Client
tdns-mgr --help resolve
```

### Verbose Help

View all available commands in one output:

```bash
# Show verbose help with all commands
tdns-mgr --help --verbose
```

---

## Authentication

### Login to DNS Server

```bash
# Interactive login (prompts for password)
tdns-mgr login

# Non-interactive login using environment variable
DNS_PASS="admin" tdns-mgr login
```

### Logout

```bash
tdns-mgr logout
```

### Change Password

```bash
# Interactive password change
tdns-mgr change-password

# Non-interactive password change
tdns-mgr change-password newpassword123
```

### View/Set Configuration

```bash
# View current configuration
tdns-mgr config show

# Set server address
tdns-mgr config set server dns.example.com

# Set port
tdns-mgr config set port 5380

# Set username
tdns-mgr config set user admin
```

---

## DNS (Zones & Records)

### Zone Management

```bash
# List all zones
tdns-mgr list-zones

# Create a primary zone
tdns-mgr create-zone example.com Primary

# Create a secondary zone
tdns-mgr create-zone example.org Secondary

# Create a stub zone
tdns-mgr create-zone internal.local Stub

# Create a conditional forwarder zone
tdns-mgr create-zone corp.local Forwarder

# Enable a zone
tdns-mgr enable-zone example.com

# Disable a zone
tdns-mgr disable-zone example.com

# Delete a zone (requires confirmation)
tdns-mgr delete-zone example.com

# Export a single zone to BIND format
tdns-mgr export-zone example.com example.com.zone

# Import a zone from BIND format
tdns-mgr import-zone example.com example.com.zone

# Export all zones to a zip file
tdns-mgr export-zones backup-$(date +%Y%m%d).zip

# Import all zones from a zip file
tdns-mgr import-zones backup-20250102.zip
```

### Record Management

```bash
# List all records in a zone
tdns-mgr list-records example.com

# Add an A record
tdns-mgr add-record example.com www A 192.168.1.100

# Add an A record with custom TTL
tdns-mgr add-record example.com mail A 192.168.1.50 7200

# Add an A record with automatic PTR creation
tdns-mgr add-record example.com server1 A 192.168.1.10 --ptr

# Add an AAAA record (IPv6)
tdns-mgr add-record example.com www AAAA 2001:db8::1

# Add a CNAME record
tdns-mgr add-record example.com ftp CNAME www.example.com

# Add an MX record
tdns-mgr add-record example.com @ MX mail.example.com 10

# Add a TXT record
tdns-mgr add-record example.com @ TXT "v=spf1 include:_spf.example.com ~all"

# Add an NS record
tdns-mgr add-record example.com @ NS ns1.example.com

# Add a PTR record
tdns-mgr add-record 1.168.192.in-addr.arpa 10 PTR server1.example.com

# Update an A record
tdns-mgr update-record example.com www A 192.168.1.100 192.168.1.101

# Update an A record with custom TTL
tdns-mgr update-record example.com www A 192.168.1.101 192.168.1.102 3600

# Delete a record
tdns-mgr delete-record example.com www A 192.168.1.102

# Delete a record without specifying value
tdns-mgr delete-record example.com ftp CNAME

# Import records from CSV file
tdns-mgr import-records dns-records.csv

# Import records with automatic PTR creation
tdns-mgr import-records dns-records.csv --ptr
```

**CSV Format for `import-records`**:

```csv
zone,name,type,value
example.com,web,A,192.168.1.20
example.com,db,A,192.168.1.21
example.com,mail,CNAME,web.example.com
```

### Server Management

```bash
# Check if server is running
tdns-mgr server-status

# Get server statistics
tdns-mgr server-stats

# Flush DNS cache
tdns-mgr flush-cache

# Query a domain
tdns-mgr query example.com A

# Query AAAA record
tdns-mgr query example.com AAAA

# Query MX record
tdns-mgr query example.com MX
```

---

## Cluster Management

### Initialize a New Cluster

```bash
# Initialize a cluster with domain name and primary node IP
tdns-mgr cluster-init cluster.example.com 192.168.10.10
```

### Join an Existing Cluster

```bash
# Join cluster (prompts for primary node password)
tdns-mgr cluster-join https://primary.cluster.example.com:5380 192.168.10.11 admin

# Join cluster with specific primary IP
tdns-mgr cluster-join https://primary.cluster.example.com:5380 192.168.10.11 admin password123 192.168.10.10

# Join cluster ignoring certificate errors
tdns-mgr cluster-join https://primary.cluster.example.com:5380 192.168.10.11 admin password123 "" true
```

### Manage Cluster

```bash
# Get cluster status
tdns-mgr cluster-status

# Get cluster status for specific node
tdns-mgr cluster-status node1.cluster.example.com

# Force resync with primary node (from secondary)
tdns-mgr cluster-resync

# Promote secondary to primary (requires confirmation)
tdns-mgr cluster-promote

# Force promote without syncing from old primary
tdns-mgr cluster-promote true

# Leave cluster (requires confirmation)
tdns-mgr cluster-leave

# Force leave without notifying primary
tdns-mgr cluster-leave true
```

---

## Administration (Users, Groups, Permissions)

### User Management

```bash
# List all users
tdns-mgr admin-user-list

# Create a user
tdns-mgr admin-user-create johndoe password123

# Create a user with display name
tdns-mgr admin-user-create janedoe password456 "Jane Doe"

# Delete a user (requires confirmation)
tdns-mgr admin-user-delete johndoe
```

### Group Management

```bash
# List all groups
tdns-mgr admin-group-list

# Create a group
tdns-mgr admin-group-create "DNS Operators"

# Create a group with description
tdns-mgr admin-group-create "Backup Admins" "Administrators with read-only access"

# Delete a group (requires confirmation)
tdns-mgr admin-group-delete "DNS Operators"
```

### Permission Management

```bash
# List all permissions
tdns-mgr admin-perm-list
```

### Session Management

```bash
# List all active sessions
tdns-mgr admin-session-list

# Delete a specific session by partial token
tdns-mgr admin-session-delete 272f4890427b9ab5

# Create an API token for a user
tdns-mgr admin-token-create admin MyAutomationToken
```

---

## DHCP Server Management

### DHCP Scope Management

```bash
# List all DHCP scopes
tdns-mgr dhcp-scope-list

# Get details of a specific scope
tdns-mgr dhcp-scope-get "Office Network"

# Create/update a DHCP scope
tdns-mgr dhcp-scope-set "Office Network" 192.168.1.100 192.168.1.200 255.255.255.0

# Create a scope with additional options
tdns-mgr dhcp-scope-set "Office Network" 192.168.1.100 192.168.1.200 255.255.255.0 \
    leaseTimeDays=7 routerAddress=192.168.1.1 dnsServers=192.168.1.10

# Enable a DHCP scope
tdns-mgr dhcp-scope-enable "Office Network"

# Disable a DHCP scope
tdns-mgr dhcp-scope-disable "Office Network"

# Delete a DHCP scope (requires confirmation)
tdns-mgr dhcp-scope-delete "Office Network"
```

### DHCP Lease Management

```bash
# List all DHCP leases
tdns-mgr dhcp-lease-list

# Remove a specific lease
tdns-mgr dhcp-lease-remove "Office Network" 00:11:22:33:44:55

# Convert a dynamic lease to reserved
tdns-mgr dhcp-lease-convert "Office Network" 00:11:22:33:44:55 Reserved

# Convert a reserved lease to dynamic
tdns-mgr dhcp-lease-convert "Office Network" 00:11:22:33:44:55 Dynamic
```

---

## Apps Management

### List Apps

```bash
# List installed apps
tdns-mgr app-list installed

# List apps available in the store
tdns-mgr app-list store
```

### Install Apps

```bash
# Install app from URL
tdns-mgr app-install "GeoIP" https://download.technitium.com/dns/apps/GeoIPApp.zip

# Install app from local file
tdns-mgr app-install "CustomApp" /path/to/CustomApp.zip
```

### Manage Apps

```bash
# Uninstall an app (requires confirmation)
tdns-mgr app-uninstall "GeoIP"

# Get app configuration
tdns-mgr app-config-get "GeoIP"

# Set app configuration
tdns-mgr app-config-set "GeoIP" "maxmindLicenseKey=your-key-here"
```

---

## Blocked & Allowed Zones

### Blocked Zones

```bash
# List all blocked zones
tdns-mgr blocked-list

# List blocked zones for specific domain
tdns-mgr blocked-list ads.example.com

# Block a domain
tdns-mgr blocked-add ads.example.com

# Block multiple domains
tdns-mgr blocked-add tracker.example.com
tdns-mgr blocked-add analytics.example.com

# Unblock a domain
tdns-mgr blocked-delete ads.example.com

# Flush all blocked zones (requires confirmation)
tdns-mgr blocked-flush
```

### Allowed Zones

```bash
# List all allowed zones
tdns-mgr allowed-list

# List allowed zones for specific domain
tdns-mgr allowed-list safe.example.com

# Allow a domain (exception to blocked list)
tdns-mgr allowed-add safe.example.com

# Remove from allowed list
tdns-mgr allowed-delete safe.example.com

# Flush all allowed zones (requires confirmation)
tdns-mgr allowed-flush
```

### Blocklist Management

```bash
# Force update of all blocklists
tdns-mgr blocklists-update
```

---

## Logging & Stats

### Log Management

```bash
# List all log files
tdns-mgr log-list

# Download a log file
tdns-mgr log-download 2025-01-02

# Download a log file with size limit (MB) and custom output name
tdns-mgr log-download 2025-01-02 10 server-log.txt

# Query logs for a specific app
tdns-mgr log-query QueryLogger QueryLoggerApp.Main pageNumber=1 entriesPerPage=100

# Query logs with filters
tdns-mgr log-query QueryLogger QueryLoggerApp.Main \
    clientIpAddress=192.168.1.50 \
    qname=example.com \
    start="2025-01-01 00:00:00" \
    end="2025-01-02 23:59:59"
```

### Statistics

```bash
# Get top clients stats (last hour, top 10)
tdns-mgr stats-top TopClients LastHour 10

# Get top domains (last day, top 20)
tdns-mgr stats-top TopDomains LastDay 20

# Get top blocked domains (last week, top 50)
tdns-mgr stats-top TopBlockedDomains LastWeek 50

# Get top clients for last month
tdns-mgr stats-top TopClients LastMonth 100

# Get server stats
tdns-mgr server-stats
```

---

## DNSSEC Management

### Sign a Zone

```bash
# Sign a zone with default settings (ECDSA, P256)
tdns-mgr dnssec-sign example.com

# Sign a zone with specific algorithm
tdns-mgr dnssec-sign example.com ECDSA P384

# Sign a zone with EDDSA
tdns-mgr dnssec-sign example.com EDDSA ED25519
```

### Unsign a Zone

```bash
# Unsign a zone (requires confirmation)
tdns-mgr dnssec-unsign example.com
```

### Get DNSSEC Status

```bash
# Get DNSSEC status and DS records for a zone
tdns-mgr dnssec-status example.com
```

---

## Advanced Zone & Server Settings

### Server Settings

```bash
# Get all server settings
tdns-mgr settings-get

# Set server settings
tdns-mgr settings-set allowRecursion=true logQueries=true

# Set multiple settings at once
tdns-mgr settings-set \
    preferIPv6=false \
    cachePrefetchEligibility=5 \
    enableDnsOverHttps=true
```

### Zone Options

```bash
# Get zone options
tdns-mgr zone-options-get example.com

# Set zone options
tdns-mgr zone-options-set example.com disabled=false

# Set zone transfer options
tdns-mgr zone-options-set example.com \
    zoneTransfer=AllowOnlyZoneNameServers \
    notify=ZoneNameServers
```

### Catalog Zones

```bash
# List all catalog zones
tdns-mgr catalog-list
```

---

## DNS Client

### Resolve DNS Queries

```bash
# Simple resolve (recursive resolver, UDP, A record)
tdns-mgr client-resolve example.com

# Resolve with specific record type
tdns-mgr client-resolve example.com AAAA

# Resolve using specific server
tdns-mgr client-resolve example.com A 8.8.8.8

# Resolve using DNS-over-HTTPS
tdns-mgr client-resolve example.com A recursive-resolver HTTPS

# Resolve using DNS-over-TLS
tdns-mgr client-resolve example.com A 1.1.1.1 TLS

# Resolve with DNSSEC validation
tdns-mgr client-resolve example.com A recursive-resolver UDP dnssec=true

# Resolve using system DNS
tdns-mgr client-resolve example.com A system-dns
```

---

## Automation Examples

### Bulk Zone Creation

```bash
#!/bin/bash
# Create multiple zones from a list

zones=(
    "example1.com"
    "example2.com"
    "example3.com"
)

for zone in "${zones[@]}"; do
    tdns-mgr create-zone "$zone" Primary
    echo "Created zone: $zone"
done
```

### Backup Script

```bash
#!/bin/bash
# Daily backup of DNS zones

DATE=$(date +%Y%m%d)
BACKUP_FILE="dns-backup-${DATE}.zip"

# Export all zones
tdns-mgr export-zones "$BACKUP_FILE"

# Move to backup directory
mv "$BACKUP_FILE" /backups/dns/

# Delete backups older than 30 days
find /backups/dns/ -name "dns-backup-*.zip" -mtime +30 -delete

echo "Backup completed: $BACKUP_FILE"
```

### Monitor Blocked Queries

```bash
#!/bin/bash
# Get daily statistics on blocked domains

DATE=$(date -d "yesterday" +%Y-%m-%d)

echo "Top 20 Blocked Domains for $DATE:"
tdns-mgr stats-top TopBlockedDomains Custom 20 \
    start="${DATE} 00:00:00" \
    end="${DATE} 23:59:59" | jq '.response.topBlockedDomains'
```

### Health Check Script

```bash
#!/bin/bash
# Check DNS server health

# Check if server is running
if tdns-mgr server-status > /dev/null 2>&1; then
    echo "✓ DNS Server is running"
else
    echo "✗ DNS Server is not accessible"
    exit 1
fi

# Get stats
STATS=$(tdns-mgr -q server-stats)

# Extract metrics using jq
QUERIES=$(echo "$STATS" | jq '.response.stats.totalQueries')
BLOCKED=$(echo "$STATS" | jq '.response.stats.totalBlocked')

echo "Total Queries: $QUERIES"
echo "Total Blocked: $BLOCKED"
```

### Cluster Status Monitoring

```bash
#!/bin/bash
# Monitor cluster health

STATUS=$(tdns-mgr -q cluster-status)

if echo "$STATUS" | jq -e '.response.clusterInitialized == true' > /dev/null; then
    echo "✓ Cluster is initialized"
    
    NODES=$(echo "$STATUS" | jq -r '.response.nodes[] | "\(.name): \(.state)"')
    echo "Cluster Nodes:"
    echo "$NODES"
else
    echo "✗ Cluster is not initialized"
fi
```

### Dynamic DNS Update

```bash
#!/bin/bash
# Update A record with current public IP

ZONE="home.example.com"
RECORD="dynamic"
CURRENT_IP=$(curl -s https://api.ipify.org)

# Get existing record
EXISTING=$(tdns-mgr -q list-records "$ZONE" | jq -r \
    ".response.records[] | select(.name==\"$RECORD.${ZONE}\") | .rData.ipAddress")

if [ "$EXISTING" != "$CURRENT_IP" ]; then
    echo "Updating $RECORD.$ZONE from $EXISTING to $CURRENT_IP"
    tdns-mgr update-record "$ZONE" "$RECORD" A "$EXISTING" "$CURRENT_IP"
else
    echo "IP address unchanged: $CURRENT_IP"
fi
```

---

## Quiet Mode for Scripting

All commands support `-q` or `--quiet` mode which suppresses informational output and returns only JSON data, perfect for parsing:

```bash
# Get zones as JSON
tdns-mgr -q list-zones | jq '.response.zones[] | .name'

# Get specific zone info
ZONE_TYPE=$(tdns-mgr -q list-zones | jq -r \
    '.response.zones[] | select(.name=="example.com") | .type')

echo "Zone type: $ZONE_TYPE"

# Check if user exists
USER_EXISTS=$(tdns-mgr -q admin-user-list | jq -e \
    '.response.users[] | select(.username=="johndoe")' > /dev/null && echo "yes" || echo "no")

echo "User exists: $USER_EXISTS"
```

---

## Error Handling

Example script with proper error handling:

```bash
#!/bin/bash
set -e

# Login first
if ! tdns-mgr login; then
    echo "Failed to login" >&2
    exit 1
fi

# Create zone
if tdns-mgr create-zone example.com Primary; then
    echo "Zone created successfully"
else
    echo "Failed to create zone" >&2
    exit 1
fi

# Add record
if tdns-mgr add-record example.com www A 192.168.1.100; then
    echo "Record added successfully"
else
    echo "Failed to add record" >&2
    exit 1
fi
```

---

For more information, see the main [README.md](README.md) or the [Technitium DNS Server API Documentation](https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md).
