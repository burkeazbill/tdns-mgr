# Technitium DNS Manager (tdns-mgr)

**Version**: 1.1.0  
**Author**: Burke Azbill  
**API Reference**: [Technitium DNS Server API](https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md)

---

## Overview

`tdns-mgr.sh` is a comprehensive command-line client for managing Technitium DNS Server via its REST API. It provides **100% coverage** of the Technitium DNS Server API functionality, enabling complete server management from the CLI.

This tool is designed for system administrators, DevOps engineers, and homelab enthusiasts who need to automate DNS operations, manage clusters, or simply prefer a terminal interface over a web GUI.

### Value Add

- **Complete API Coverage**: `tdns-mgr` implements every major API endpoint (as of Technitium DNS Server Version 14.3), including Cluster, DHCP, and Apps management.
- **Ease of Use**: Features an interactive help menu with categorized commands and subtle colorization for better readability. Topic-specific help available via `tdns-mgr --help <topic>`.
- **Cross-Platform**: Uses `#!/usr/bin/env bash` shebang for maximum portability across Linux, macOS, and other Unix-like systems.
- **Automation Ready**: Designed with a `-q` (quiet) mode that outputs pure JSON, making it perfect for piping into `jq` or integrating into other scripts and CI/CD pipelines.
- **Secure**: Handles authentication securely with token storage and supports non-interactive login via environment variables.
- **Zero Dependencies**: Written in pure Bash (requires only `curl`, `jq`, and `awk`), ensuring it runs on virtually any Linux/Unix system without complex Python/Go runtime requirements.

### Key Features

- ✅ **Cluster Management** - Initialize, join, sync, and manage DNS clusters.
- ✅ **DHCP Server** - Manage scopes, leases, and reservations.
- ✅ **DNS Apps** - Install, configure, and manage DNS Apps from the store or URL.
- ✅ **DNSSEC** - Fully manage DNSSEC signing, keys, and status.
- ✅ **Zone & Record Management** - Complete control over zones and records (A, AAAA, CNAME, etc.).
- ✅ **Administration** - User/Group management, permissions, and API tokens.
- ✅ **Logging & Stats** - Query logs, download log files, and view server statistics.
- ✅ **Blocklists** - Manage blocked/allowed zones and force blocklist updates.

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

## Documentation & Examples

Detailed usage examples for every command category can be found in the [**EXAMPLES.md**](EXAMPLES.md) file.

**[View EXAMPLES.md](EXAMPLES.md)**

The examples cover:

- Basic Authentication
- Creating and managing Zones
- Adding and updating DNS Records
- Setting up High Availability Clusters
- Managing DHCP Scopes and Leases
- Installing DNS Apps
- Configuring DNSSEC
- Advanced Server Settings

---

## Quick Start

1. **Configure Connection**:

    ```bash
    tdns-mgr config set server dns.example.com
    tdns-mgr config set user admin
    ```

2. **Login**:

    ```bash
    tdns-mgr login
    ```

3. **Run Commands**:

    ```bash
    tdns-mgr list-zones
    tdns-mgr server-stats
    ```

### Help System

The script features a hierarchical help system:

- **Summary Help** (default): Shows available help topics
  ```bash
  tdns-mgr --help
  ```

- **Topic-Specific Help**: Get detailed help for specific topics
  ```bash
  tdns-mgr --help Authentication
  tdns-mgr --help DNS
  tdns-mgr --help Cluster
  ```

- **Verbose Help**: View all commands at once
  ```bash
  tdns-mgr --help --verbose
  ```

Available help topics: `Authentication`, `DNS`, `Cluster`, `Administration`, `DHCP`, `Apps`, `Blocked`, `Logging`, `DNSSEC`, `Settings`, `Client`

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

## Support

For issues or questions:

1. Check the [Technitium DNS Server documentation](https://github.com/TechnitiumSoftware/DnsServer)
2. Review the [API documentation](https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md)

---

## License

© Burke Azbill

This tool is provided open source under the MIT License.
