# Changelog

## Version 1.2.0 (2026-01-26)

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

---

## Version 1.1.1 (Previous)

- Enhanced help system with hierarchical topics
- Added 100% Technitium DNS Server API coverage
- Cross-platform compatibility improvements
- Configuration file precedence system
- Debug mode for troubleshooting
