# Login Command Improvements (v1.2.0)

## Summary

The `tdns-mgr login` command has been completely rewritten to address all reported issues and provide a comprehensive, user-friendly authentication experience.

## Issues Resolved

### 1. ✅ Interactive Setup When Config Doesn't Exist

**Previous Behavior**: Login command didn't step through full interactive setup when configuration file didn't exist.

**New Behavior**: When no configuration file exists, the `login` command now prompts for ALL required values:
- DNS Server address
- DNS Server port
- Protocol (http/https)
- Username
- Password

```bash
# First-time setup - prompts for everything
$ tdns-mgr login
DNS Server [localhost]: dns.example.com
DNS Port [5380]: 5380
Protocol (http/https) [https]: https
Username [admin]: admin
Password: ********
```

### 2. ✅ Password as Command-Line Argument

**Previous Behavior**: No `-p` flag to pass password as argument.

**New Behavior**: Password can now be passed via `-p` or `--password` flag:

```bash
# Login with password argument
tdns-mgr login -p mypassword

# Full non-interactive login
tdns-mgr login -s dns.example.com -P 5380 --protocol https -u admin -p mypassword
```

### 3. ✅ All Config Values via Login Command

**Previous Behavior**: Had to use `config set` command separately to configure values.

**New Behavior**: All configuration values can now be provided via `login` command arguments:

```bash
# Set server and login
tdns-mgr login -s dns.example.com -p mypassword

# Set multiple values
tdns-mgr login -s dns.example.com -P 8080 -u newuser -p mypassword

# Complete configuration
tdns-mgr login -s dns.example.com -P 5380 --protocol https -u admin -p mypassword
```

### 4. ✅ Update Existing Configuration

**Previous Behavior**: No way to update existing configuration via login command.

**New Behavior**: New `--update` flag forces interactive re-configuration:

```bash
# Interactive update of all values (shows current values as defaults)
tdns-mgr login --update

# Update specific values only
tdns-mgr login -s new-server.com -p mypassword
tdns-mgr login -u newuser -p mypassword
```

## New Command-Line Arguments

| Argument | Short | Description |
|----------|-------|-------------|
| `--server` | `-s` | DNS server address |
| `--port` | `-P` | DNS server port |
| `--protocol` | | Protocol (http or https) |
| `--user` | `-u` | Username |
| `--password` | `-p` | Password |
| `--update` | | Force update of existing config |

## Login Behavior Flow

### Scenario 1: First-Time Setup (No Config File)

```bash
$ tdns-mgr login
# Prompts for: server, port, protocol, username, password
# Creates config file at: ~/.config/tdns-mgr/.tdns-mgr.conf
```

### Scenario 2: Login with Existing Config

```bash
$ tdns-mgr login
# Uses saved values for: server, port, protocol, username
# Only prompts for: password
# Updates token in config file
```

### Scenario 3: Non-Interactive with Arguments

```bash
$ tdns-mgr login -s dns.example.com -u admin -p mypassword
# Uses provided arguments
# Prompts for any missing required values
# Saves to config file
```

### Scenario 4: Update Existing Config

```bash
$ tdns-mgr login --update
# Shows current values as defaults
# Allows interactive update of any value
# Saves updated config
```

### Scenario 5: Partial Update

```bash
$ tdns-mgr login -s new-server.com -p mypassword
# Updates only the server address
# Keeps other existing config values
# Re-authenticates and saves new token
```

## Smart Features

### 1. Token Validation

If a valid token already exists in the config, the login command validates it first:

```bash
$ tdns-mgr login -p mypassword
ℹ Using existing authentication token
✓ Already logged in as admin
```

If the token is invalid, it automatically re-authenticates:

```bash
$ tdns-mgr login -p mypassword
⚠ Existing token is invalid, need to re-authenticate
ℹ Logging in to DNS Server at dns.example.com:5380
✓ Successfully logged in as admin
```

### 2. Intelligent Prompting

The command only prompts for values that are:
- Not provided via arguments
- Required for authentication
- Being updated (when `--update` flag is used)

### 3. Backward Compatibility

The login command remains fully backward compatible:

```bash
# Still works - prompts for password only
tdns-mgr login

# Still works - uses environment variable
DNS_PASS=mypassword tdns-mgr login
```

## Usage Examples

### For New Users

```bash
# Easiest: Interactive setup
tdns-mgr login

# Quick: One-line setup
tdns-mgr login -s dns.example.com -u admin -p mypassword
```

### For Automation/Scripting

```bash
# Fully automated login (no prompts)
tdns-mgr login -s dns.example.com -P 5380 --protocol https -u admin -p "$PASSWORD"

# Or using environment variable
DNS_PASS="$PASSWORD" tdns-mgr login
```

### For Updating Configuration

```bash
# Change server
tdns-mgr login -s new-server.com -p mypassword

# Change port
tdns-mgr login -P 8080 -p mypassword

# Change user
tdns-mgr login -u newuser -p mypassword

# Change everything interactively
tdns-mgr login --update
```

### For Daily Use

```bash
# Quick login with saved config
tdns-mgr login -p mypassword

# Or with environment variable
export DNS_PASS=mypassword
tdns-mgr login
```

## Configuration File Management

The enhanced login command automatically:

1. Creates `~/.config/tdns-mgr/` directory if it doesn't exist
2. Saves configuration to `~/.config/tdns-mgr/.tdns-mgr.conf`
3. Preserves existing values when updating specific settings
4. Updates authentication token after successful login
5. Provides clear feedback about where config is saved

## Error Handling

The command validates all inputs and provides clear error messages:

```bash
# Missing required values
✗ All fields are required for login

# Invalid credentials
✗ Login failed
{
  "status": "error",
  "errorMessage": "Invalid credentials"
}

# Network issues (handled by underlying API functions)
✗ Failed to connect to DNS server
```

## Documentation Updates

All documentation has been updated to reflect the new capabilities:

1. **Built-in Help**: `tdns-mgr --help authentication`
2. **README.md**: Updated Quick Start section
3. **EXAMPLES.md**: Comprehensive authentication examples
4. **CHANGELOG.md**: Full list of changes

## Testing

To test the new functionality:

```bash
# Test help display
tdns-mgr --help authentication

# Test syntax
bash -n tdns-mgr.sh

# Test version
tdns-mgr --version

# Test with your DNS server
tdns-mgr login -s your-server -u admin -p yourpassword
```

## Migration Guide

If you're upgrading from v1.1.x:

1. **No action required** - Existing config files work as-is
2. **Optional**: Try `tdns-mgr login --update` to experience new interactive features
3. **Benefit**: Can now pass password via `-p` for scripting/automation

## Future Enhancements

Potential future improvements:
- Support for multiple server profiles
- Secure credential storage integration (e.g., keychain)
- API key authentication (when supported by Technitium DNS Server)

---

**Version**: 1.2.0  
**Date**: 2026-01-26  
**Author**: Burke Azbill
