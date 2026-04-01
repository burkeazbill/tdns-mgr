# Changelog

## Version 1.2.2 (2026-04-01)

### Major Enhancements - Login & Configuration

#### Enhanced Login Command

The `login` command has been completely rewritten to provide flexible authentication options:

**New Command-Line Arguments:**
- `-s, --server SERVER` - Specify DNS server address
- `-P, --port PORT` - Specify DNS server port  
- `--protocol PROTOCOL` - Specify protocol (http/https)
- `-u, --user USER` - Specify username
- `-p, --password PASSWORD` - Specify password as argument
- `--update` - Force interactive update of existing configuration

**Behavior Improvements:**

1. **First-Time Setup**: When no configuration file exists, `login` prompts for all required values (server, port, protocol, username, password) interactively.

2. **Existing Config Login**: When a configuration file exists, `login` uses saved values and only prompts for password (unless overridden with arguments).

3. **Partial Configuration**: Can specify only some values via arguments, and the command will prompt for missing required values.

4. **Update Mode**: Using `--update` flag forces interactive prompts for all values, allowing easy reconfiguration.

5. **Smart Token Validation**: If a token already exists, the command validates it first and only re-authenticates if needed.

**Examples:**

```bash
# First-time interactive setup
tdns-mgr login

# Non-interactive with all parameters
tdns-mgr login -s dns.example.com -P 5380 --protocol https -u admin -p mypassword

# Quick login with password argument
tdns-mgr login -p mypassword

# Update server address
tdns-mgr login -s new-server.com -p mypassword

# Force reconfiguration
tdns-mgr login --update
```

### Documentation Updates

- **README.md**: Updated Quick Start section with comprehensive login examples
- **EXAMPLES.md**: Expanded Authentication section with detailed usage scenarios
- **Built-in Help**: Enhanced `--help authentication` with all new options

### Fixed Issues

1. Login command now properly performs interactive setup when config doesn't exist
2. Password can now be passed via `-p` argument for automation
3. All required config values can be provided via login command
4. Existing configurations can be updated via `--update` flag

### Security Enhancements

- **TLS Verification**: Added an `--insecure` CLI flag and `INSECURE_TDNS` environment variable to explicitly allow bypassing TLS certificate verification. The script now enforces secure TLS verification by default (removed hardcoded `curl -sk`).
- **Secure Configuration Directory**: The configuration directory (`~/.config/tdns-mgr`) is now created with strict `700` permissions.

### Performance Improvements

- **CSV Parsing Optimization**: Greatly improved performance for `import-records` and `delete-records` by replacing the line-by-line `awk` subshell execution with a single, fast `awk` pass that generates a temporary pipe-delimited file.
- **Useless Use of Cat (UUOC)**: Replaced `done < <(cat "$file")` with direct file redirection `done < "$file"`.

### Bug Fixes

- **API Payload Corruption**: Fixed a critical bug where API payloads were built using insecure string concatenation (e.g. `user=$DNS_USER&pass=$DNS_PASS`), which corrupted requests if values contained `&`, `=`, or `+`. The script now securely URL-encodes all parameters using `curl --data-urlencode`.
- **JSON Parsing**: The `login` command now properly uses `jq` to parse the authentication token, replacing brittle `grep` and `cut` commands.

---

## Version 1.1.1 (Previous)

- Enhanced help system with hierarchical topics
- Added 100% Technitium DNS Server API coverage
- Cross-platform compatibility improvements
- Configuration file precedence system
- Debug mode for troubleshooting
