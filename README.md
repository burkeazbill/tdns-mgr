# Technitium DNS Manager (tdns-mgr)

**Version**: 1.1.1  
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

> [!WARNING]
While 100% of the API has been covered by this script, only the DNS Zones and Record management functions have been tested by the author as that is his only requirement at the time of commiting this script.

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

Available help topics: `Authentication`, `DNS`, `Cluster`, `Administration`, `DHCP`, `Apps`, `Blocked`, `Logging`, `DNSSEC`, `Settings`, `Client`, `Completion`

### Shell Completion

The script provides shell completion for command names, options, and common arguments, enhancing the command-line experience.

#### Generating Completion Scripts

To generate a completion script for your shell:

```bash
# For Bash
tdns-mgr completion bash

# For Zsh
tdns-mgr completion zsh

# For Fish
tdns-mgr completion fish
```

#### Installation Instructions

**Bash Completion:**

System-wide installation (requires sudo):
```bash
tdns-mgr completion bash | sudo tee /etc/bash_completion.d/tdns-mgr > /dev/null
```

Per-user installation:
```bash
mkdir -p ~/.local/share/bash-completion/completions
tdns-mgr completion bash > ~/.local/share/bash-completion/completions/tdns-mgr
```

Then reload your shell or source the completion file:
```bash
source ~/.local/share/bash-completion/completions/tdns-mgr
```

**Zsh Completion:**

System-wide installation (requires sudo):
```bash
tdns-mgr completion zsh | sudo tee /usr/share/zsh/site-functions/_tdns-mgr > /dev/null
```

Per-user installation:
```bash
mkdir -p ~/.zsh/completion
tdns-mgr completion zsh > ~/.zsh/completion/_tdns-mgr
```

Add to your `~/.zshrc` if not already present:
```bash
fpath=(~/.zsh/completion $fpath)
autoload -Uz compinit
compinit
```

Then reload your shell:
```bash
exec zsh
```

**Fish Completion:**

System-wide installation (requires sudo):
```bash
tdns-mgr completion fish | sudo tee /usr/share/fish/vendor_completions.d/tdns-mgr.fish > /dev/null
```

Per-user installation:
```bash
mkdir -p ~/.config/fish/completions
tdns-mgr completion fish > ~/.config/fish/completions/tdns-mgr.fish
```

Fish will automatically load the completion on next shell start or you can reload:
```bash
source ~/.config/fish/completions/tdns-mgr.fish
```

---

## Configuration

### Configuration File Locations

The script checks for configuration in the following order:

1. **Command-line environment variables** (highest priority)
2. **User config**: `~/.config/tdns-mgr/.tdns-mgr.conf`
3. **System config**: `/etc/tdns-mgr/.tdns-mgr.conf`
4. **Script directory**: `<script-dir>/.tdns-mgr.conf` (backward compatibility)

When saving configuration (via `login` or `config set`), it saves to: `~/.config/tdns-mgr/.tdns-mgr.conf`

The directory is automatically created if it doesn't exist.

### Configuration File Format

```bash
DNS_SERVER="localhost"
DNS_PORT="5380"
DNS_PROTOCOL="https"
DNS_TOKEN="your-auth-token-here"
DNS_USER="admin"
```

### Environment Variables

You can override configuration using environment variables (highest priority):

```bash
export DNS_SERVER="dns.example.com"
export DNS_PORT="5380"
export DNS_PROTOCOL="https"  # Use "http" or "https" (default: https)
export DNS_USER="admin"
export DNS_PASS="password"  # For non-interactive login
export DNS_TOKEN="token"     # Skip login if token is set
```

### View Current Configuration

### SSL Notes

- The script does not validate SSL certificates by default (curl's standard behavior)
- To ignore SSL certificate errors for self-signed certificates, users can set:

  ```bash
  alias tdns-mgr='CURL_CA_BUNDLE="" tdns-mgr'
  ```

  Or modify curl commands in the script to add `-k` flag if needed

```bash
# Show which config file is being used and current values
tdns-mgr config show
```

---

## Support

For issues or questions:

1. Check the [Technitium DNS Server documentation](https://github.com/TechnitiumSoftware/DnsServer)
2. Review the [API documentation](https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md)

---

## Other Technitium DNS Server Scripts or Tools

> [!NOTE]
I found other CLI tools after I had written this one. I have not used these.
- **tdns CLI** - Cross platform management tool written in Golang and is available at [https://github.com/mbevc1/tdns](https://github.com/mbevc1/tdns).
- **TechnitiumDNS-Scripts** - Interactive Python script written to manage DHCP Scope Reservations, available at [https://github.com/mbevc1/tdns](https://github.com/mbevc1/tdns)

## License

© Burke Azbill

This tool is provided open source under the MIT License.
