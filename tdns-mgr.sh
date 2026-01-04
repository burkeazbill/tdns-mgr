#!/usr/bin/env bash

################################################################################
# DNS Manager - Technitium DNS Server API Client
# © Burke Azbill
# Licensed under MIT License - see LICENSE.md
# 
# Full implementation of Technitium DNS Server API
# API Documentation: https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md
#
# Usage: tdns-mgr.sh [options] [command] [args]
################################################################################

set -euo pipefail

# Version
VERSION="1.1.0"

# Colors for output (check if terminal supports colors)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[38;2;0;176;255m'
    CYAN='\033[0;36m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    NC=''
fi

# Configuration file
# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Configuration file locations (in order of precedence)
# 1. User config directory (default save location)
USER_CONFIG_FILE="${HOME}/.config/tdns-mgr/.tdns-mgr.conf"
# 2. System-wide config
SYSTEM_CONFIG_FILE="/etc/tdns-mgr/.tdns-mgr.conf"
# 3. Script directory (backward compatibility)
SCRIPT_CONFIG_FILE="${SCRIPT_DIR}/.tdns-mgr.conf"

# Default values
DNS_SERVER="${DNS_SERVER:-localhost}"
DNS_PORT="${DNS_PORT:-5380}"
DNS_PROTOCOL="${DNS_PROTOCOL:-https}"
DNS_TOKEN="${DNS_TOKEN:-}"
DNS_USER="${DNS_USER:-admin}"
DNS_PASS="${DNS_PASS:-}"
QUIET="${QUIET:-false}"
DEBUG="${DEBUG:-false}"

# This will be set by load_config to the actual file that was loaded
CONFIG_FILE="${USER_CONFIG_FILE}"

################################################################################
# Helper Functions
################################################################################

print_header() {
    if [[ "$QUIET" == "false" ]]; then
        echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}" >&2
        echo -e "${CYAN}║${NC}                    ${BLUE}Technitium DNS Manager ${NC}                     ${CYAN}║${NC}" >&2
        echo -e "${CYAN}║${NC}                        Version ${VERSION}                           ${CYAN}║${NC}" >&2
        echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}" >&2
        echo "" >&2
    fi
}

print_success() {
    if [[ "$QUIET" == "false" ]]; then
        echo -e "${GREEN}✓${NC} $1" >&2
    fi
}

print_error() {
    echo -e "${RED}✗${NC} $1" >&2
}

print_warning() {
    if [[ "$QUIET" == "false" ]]; then
        echo -e "${YELLOW}⚠${NC} $1" >&2
    fi
}

print_info() {
    if [[ "$QUIET" == "false" ]]; then
        echo -e "${BLUE}ℹ${NC} $1" >&2
    fi
}

print_debug() {
    if [[ "$DEBUG" == "true" ]]; then
        echo -e "${YELLOW}[DEBUG]${NC} $1" >&2
    fi
}

# Load configuration
load_config() {
    # Configuration precedence order:
    # 1. Command-line environment variables (already loaded as defaults above)
    # 2. User config directory: ~/.config/tdns-mgr/.tdns-mgr.conf
    # 3. System-wide config: /etc/tdns-mgr/.tdns-mgr.conf
    # 4. Script directory: SCRIPT_DIR/.tdns-mgr.conf (backward compatibility)
    
    local config_loaded="none (using defaults or env vars)"

    # Check user config directory
    if [[ -f "$USER_CONFIG_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$USER_CONFIG_FILE"
        CONFIG_FILE="$USER_CONFIG_FILE"
        config_loaded="$USER_CONFIG_FILE"
    # Check system-wide config
    elif [[ -f "$SYSTEM_CONFIG_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$SYSTEM_CONFIG_FILE"
        CONFIG_FILE="$SYSTEM_CONFIG_FILE"
        config_loaded="$SYSTEM_CONFIG_FILE"
    # Check script directory (backward compatibility)
    elif [[ -f "$SCRIPT_CONFIG_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$SCRIPT_CONFIG_FILE"
        CONFIG_FILE="$SCRIPT_CONFIG_FILE"
        config_loaded="$SCRIPT_CONFIG_FILE"
    fi
    
    print_debug "Configuration loaded from: $config_loaded"
    print_debug "Environment Variables:"
    print_debug "  DNS_SERVER: $DNS_SERVER"
    print_debug "  DNS_PORT: $DNS_PORT"
    print_debug "  DNS_PROTOCOL: $DNS_PROTOCOL"
    print_debug "  DNS_USER: $DNS_USER"
    if [[ -n "$DNS_PASS" ]]; then
        print_debug "  DNS_PASS: ***************"
    else
        print_debug "  DNS_PASS: (not set)"
    fi
    if [[ -n "$DNS_TOKEN" ]]; then
        print_debug "  DNS_TOKEN: ***************"
    else
        print_debug "  DNS_TOKEN: (not set)"
    fi

    # Note: Command-line arguments (environment variables) take precedence
    # They are already set as defaults before this function is called
}

# Save configuration
save_config() {
    # Ensure the config directory exists
    local config_dir=$(dirname "$USER_CONFIG_FILE")
    if [[ ! -d "$config_dir" ]]; then
        mkdir -p "$config_dir"
        if [[ $? -ne 0 ]]; then
            print_error "Failed to create config directory: $config_dir"
            return 1
        fi
    fi
    
    # Save to user config file
    cat > "$USER_CONFIG_FILE" << EOF
DNS_SERVER="$DNS_SERVER"
DNS_PORT="$DNS_PORT"
DNS_PROTOCOL="$DNS_PROTOCOL"
DNS_TOKEN="$DNS_TOKEN"
DNS_USER="$DNS_USER"
EOF
    
    if [[ $? -ne 0 ]]; then
        print_error "Failed to save configuration to $USER_CONFIG_FILE"
        return 1
    fi
    
    chmod 600 "$USER_CONFIG_FILE"
    CONFIG_FILE="$USER_CONFIG_FILE"
    print_success "Configuration saved to $USER_CONFIG_FILE"
}

# API call wrapper
api_call() {
    local endpoint="$1"
    shift
    local url="${DNS_PROTOCOL}://${DNS_SERVER}:${DNS_PORT}/api/${endpoint}"
    
    # For debug output, mask sensitive information
    if [[ "$DEBUG" == "true" ]]; then
        local masked_args=()
        for arg in "$@"; do
            local masked_arg="$arg"
            # Mask token, pass, and password in URL-encoded data
            masked_arg=$(echo "$masked_arg" | sed 's/\(^\|&\)token=[^&]*/\1token=***************/g')
            masked_arg=$(echo "$masked_arg" | sed 's/\(^\|&\)pass=[^&]*/\1pass=***************/g')
            masked_arg=$(echo "$masked_arg" | sed 's/\(^\|&\)password=[^&]*/\1password=***************/g')
            masked_args+=("$masked_arg")
        done
        
        local debug_cmd="curl -s -X POST \"$url\""
        if [[ -n "$DNS_TOKEN" ]]; then
            debug_cmd="$debug_cmd -H \"Authorization: Bearer ***************\""
        fi
        print_debug "Executing: $debug_cmd ${masked_args[*]}"
    fi

    local response
    if [[ -n "$DNS_TOKEN" ]]; then
        response=$(curl -s -X POST "$url" \
            -H "Authorization: Bearer $DNS_TOKEN" \
            "$@")
    else
        response=$(curl -s -X POST "$url" "$@")
    fi
    
    print_debug "API Response: $response"
    echo "$response"
}

# API call with data
api_post() {
    local endpoint="$1"
    shift
    api_call "$endpoint" -d "$@"
}

# Check if authenticated
check_auth() {
    if [[ -z "$DNS_TOKEN" ]]; then
        print_error "Not authenticated. Please run: tdns-mgr.sh login"
        exit 1
    fi
}

# Check dependencies
check_dependencies() {
    local deps=("curl" "jq" "awk")
    local missing=()
    
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -eq 0 ]]; then
        return 0
    fi
    
    print_warning "Missing required dependencies: ${missing[*]}"
    
    if [[ "$QUIET" == "true" ]]; then
        print_error "Cannot install dependencies in quiet mode. Please install them manually."
        exit 1
    fi
    
    echo -n "Would you like to install them now? (y/n): " >&2
    read -r confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_error "Cannot proceed without dependencies. Exiting."
        exit 1
    fi
    
    local pkg_cmd=""
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "$ID" in
            debian|ubuntu|kali|raspbian|pop|linuxmint)
                pkg_cmd="sudo apt-get update && sudo apt-get install -y"
                ;;
            fedora|rhel|centos|almalinux|rocky)
                pkg_cmd="sudo dnf install -y" 2>/dev/null || pkg_cmd="sudo yum install -y"
                ;;
            alpine)
                pkg_cmd="sudo apk add"
                ;;
            arch|manjaro|endeavouros)
                pkg_cmd="sudo pacman -S --noconfirm"
                ;;
            opensuse*)
                pkg_cmd="sudo zypper install -y"
                ;;
        esac
    fi
    
    # MacOS check
    if [[ "$(uname)" == "Darwin" ]]; then
        if command -v brew &> /dev/null; then
            pkg_cmd="brew install"
        else
            print_error "Homebrew not found. Please install dependencies manually."
            exit 1
        fi
    fi
    
    if [[ -z "$pkg_cmd" ]]; then
        print_error "Unsupported operating system. Please install ${missing[*]} manually."
        exit 1
    fi
    
    print_info "Installing dependencies..."
    $pkg_cmd "${missing[@]}"
    print_success "Dependencies installed."
}

################################################################################
# Authentication Functions
################################################################################

cmd_login() {
    print_info "Logging in to DNS Server at ${DNS_SERVER}:${DNS_PORT}"
    
    if [[ -z "$DNS_PASS" ]]; then
        read -sp "Password: " DNS_PASS
        echo "" >&2
    fi
    
    local response=$(api_post "user/login" "user=${DNS_USER}&pass=${DNS_PASS}")
    
    if echo "$response" | grep -q '"status":"ok"'; then
        DNS_TOKEN=$(echo "$response" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
        save_config
        print_success "Successfully logged in"
        print_info "Token: ${DNS_TOKEN:0:20}..."
    else
        print_error "Login failed"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
        exit 1
    fi
}

cmd_logout() {
    check_auth
    api_post "user/logout" "token=${DNS_TOKEN}" > /dev/null
    DNS_TOKEN=""
    save_config
    print_success "Logged out successfully"
}

cmd_change_password() {
    check_auth
    local new_pass="$1"
    
    if [[ -z "$new_pass" ]]; then
        read -sp "New password: " new_pass
        echo "" >&2
    fi
    
    local response=$(api_post "user/changePassword" "token=${DNS_TOKEN}&pass=${new_pass}")
    
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Password changed successfully"
    else
        print_error "Failed to change password"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_check_update() {
    check_auth
    print_info "Checking for DNS server updates..."
    
    local response=$(api_get "user/checkForUpdate" "token=${DNS_TOKEN}")
    
    if echo "$response" | grep -q '"status":"ok"'; then
        local update_available=$(echo "$response" | jq -r '.response.updateAvailable // false')
        local current_version=$(echo "$response" | jq -r '.response.currentVersion // "unknown"')
        local update_version=$(echo "$response" | jq -r '.response.updateVersion // "unknown"')
        
        if [[ "$update_available" == "true" ]]; then
            print_warning "Update available!"
            print_info "Current version: $current_version"
            print_info "Available version: $update_version"
        else
            print_success "Server is up to date"
            print_info "Current version: $current_version"
        fi
        
        # In quiet mode, just output the JSON
        if [[ "$QUIET" == "true" ]]; then
            echo "$response" | jq '.'
        fi
    else
        print_error "Failed to check for updates"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

################################################################################
# Zone Management Functions
################################################################################

cmd_list_zones() {
    check_auth
    print_info "Listing DNS zones..."
    
    local response=$(api_post "zones/list" "token=${DNS_TOKEN}")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

cmd_create_zone() {
    check_auth
    local zone="$1"
    local type="${2:-Primary}"
    
    if [[ -z "$zone" ]]; then
        print_error "Usage: tdns-mgr.sh create-zone <domain> [type]"
        print_info "Types: Primary, Secondary, Stub, Forwarder"
        exit 1
    fi
    
    print_info "Creating zone: $zone (Type: $type)"
    
    local response=$(api_post "zones/create" "token=${DNS_TOKEN}&zone=${zone}&type=${type}")
    
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Zone created: $zone"
    else
        print_error "Failed to create zone"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_delete_zone() {
    check_auth
    local zone="$1"
    
    if [[ -z "$zone" ]]; then
        print_error "Usage: tdns-mgr.sh delete-zone <domain>"
        exit 1
    fi
    
    print_warning "Deleting zone: $zone"
    read -p "Are you sure? (yes/no): " confirm
    
    if [[ "$confirm" != "yes" ]]; then
        print_info "Cancelled"
        exit 0
    fi
    
    local response=$(api_post "zones/delete" "token=${DNS_TOKEN}&zone=${zone}")
    
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Zone deleted: $zone"
    else
        print_error "Failed to delete zone"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_enable_zone() {
    check_auth
    local zone="$1"
    
    if [[ -z "$zone" ]]; then
        print_error "Usage: tdns-mgr.sh enable-zone <domain>"
        exit 1
    fi
    
    local response=$(api_post "zones/enable" "token=${DNS_TOKEN}&zone=${zone}")
    
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Zone enabled: $zone"
    else
        print_error "Failed to enable zone"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_disable_zone() {
    check_auth
    local zone="$1"
    
    if [[ -z "$zone" ]]; then
        print_error "Usage: tdns-mgr.sh disable-zone <domain>"
        exit 1
    fi
    
    local response=$(api_post "zones/disable" "token=${DNS_TOKEN}&zone=${zone}")
    
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Zone disabled: $zone"
    else
        print_error "Failed to disable zone"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_export_zone() {
    check_auth
    local zone="$1"
    local file="${2:-${zone}.txt}"
    
    if [[ -z "$zone" ]]; then
        print_error "Usage: tdns-mgr.sh export-zone <domain> [file]"
        exit 1
    fi
    
    print_info "Exporting zone $zone to $file (BIND format)..."
    
    local url="${DNS_PROTOCOL}://${DNS_SERVER}:${DNS_PORT}/api/zones/export?token=${DNS_TOKEN}&zone=${zone}&format=Bind"
    
    if curl -s -f "$url" -o "$file"; then
        print_success "Zone exported to $file"
    else
        print_error "Failed to export zone"
        exit 1
    fi
}

cmd_import_zone() {
    check_auth
    local zone="$1"
    local file="$2"
    
    if [[ -z "$zone" || -z "$file" ]]; then
        print_error "Usage: tdns-mgr.sh import-zone <domain> <file>"
        exit 1
    fi
    
    if [[ ! -f "$file" ]]; then
        print_error "File not found: $file"
        exit 1
    fi
    
    print_info "Importing zone $zone from $file..."
    
    local url="${DNS_PROTOCOL}://${DNS_SERVER}:${DNS_PORT}/api/zones/import?token=${DNS_TOKEN}&zone=${zone}&overwrite=true"
    
    local response=$(curl -s -X POST "$url" -F "file=@$file")
    
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Zone imported successfully"
    else
        print_error "Failed to import zone"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_export_zones() {
    check_auth
    local date_str=$(date +%Y%m%d-%H%M%S)
    local file="${1:-dns-zones-export-${date_str}.zip}"
    
    # Ensure filename ends with .zip
    if [[ "$file" != *".zip" ]]; then
        file="${file}.zip"
    fi
    
    print_info "Exporting all zones to $file..."
    
    local url="${DNS_PROTOCOL}://${DNS_SERVER}:${DNS_PORT}/api/settings/backup?token=${DNS_TOKEN}&zones=true"
    
    if curl -s -f "$url" -o "$file"; then
        print_success "All zones exported to $file"
    else
        print_error "Failed to export zones"
        exit 1
    fi
}

cmd_import_zones() {
    check_auth
    local file="$1"
    
    if [[ -z "$file" ]]; then
        print_error "Usage: tdns-mgr.sh import-zones <zip_file>"
        exit 1
    fi
    
    if [[ ! -f "$file" ]]; then
        print_error "File not found: $file"
        exit 1
    fi
    
    print_warning "This will import ALL zones from the backup, overwriting existing ones."
    read -p "Are you sure? (yes/no): " confirm
    
    if [[ "$confirm" != "yes" ]]; then
        print_info "Cancelled"
        exit 0
    fi
    
    print_info "Importing zones from $file..."
    
    local url="${DNS_PROTOCOL}://${DNS_SERVER}:${DNS_PORT}/api/settings/restore?token=${DNS_TOKEN}&zones=true&deleteExistingFiles=true"
    
    local response=$(curl -s -X POST "$url" -F "file=@$file")
    
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Zones imported successfully"
    else
        print_error "Failed to import zones"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

################################################################################
# DNS Records Management Functions
################################################################################

cmd_list_records() {
    check_auth
    local zone="$1"
    
    if [[ -z "$zone" ]]; then
        print_error "Usage: tdns-mgr.sh list-records <domain>"
        exit 1
    fi
    
    print_info "Listing records for zone: $zone"
    
    local response=$(api_post "zones/records/get" "token=${DNS_TOKEN}&domain=${zone}&listZone=true")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

cmd_add_record() {
    check_auth
    local zone="$1"
    local name="$2"
    local type="$3"
    local value="$4"
    local ttl="3600"
    local create_ptr="false"
    
    # Parse optional arguments (ttl and --ptr)
    shift 4
    for arg in "$@"; do
        if [[ "$arg" == "--ptr" ]]; then
            create_ptr="true"
        elif [[ "$arg" =~ ^[0-9]+$ ]]; then
            ttl="$arg"
        fi
    done
    
    if [[ -z "$zone" || -z "$name" || -z "$type" || -z "$value" ]]; then
        print_error "Usage: tdns-mgr.sh add-record <zone> <name> <type> <value> [ttl] [--ptr]"
        print_info "Types: A, AAAA, CNAME, MX, TXT, NS, PTR, SRV, CAA"
        print_info "Example: tdns-mgr.sh add-record example.com www A 192.168.1.100 --ptr"
        exit 1
    fi
    
    print_info "Adding $type record: $name.$zone -> $value"
    
    # Ensure domain is FQDN for the API
    local domain_name="$name"
    if [[ "$name" == "@" ]]; then
        domain_name="$zone"
    elif [[ "$name" != *".$zone" ]]; then
        domain_name="$name.$zone"
    fi
    
    local data="token=${DNS_TOKEN}&zone=${zone}&domain=${domain_name}&type=${type}&ttl=${ttl}"
    
    if [[ "$type" == "A" || "$type" == "AAAA" ]]; then
        if [[ "$create_ptr" == "true" ]]; then
            data="${data}&ptr=true&createPtrZone=true"
            print_info "Enabled automatic PTR record creation"
        fi
    fi
    
    case "$type" in
        A|AAAA)
            data="${data}&ipAddress=${value}"
            ;;
        CNAME)
            data="${data}&cname=${value}"
            ;;
        MX)
            local priority="${6:-10}"
            data="${data}&exchange=${value}&preference=${priority}"
            ;;
        TXT)
            data="${data}&text=${value}"
            ;;
        NS)
            data="${data}&nameServer=${value}"
            ;;
        PTR)
            data="${data}&ptrName=${value}"
            ;;
        *)
            print_error "Unsupported record type: $type"
            exit 1
            ;;
    esac
    
    local response=$(api_post "zones/records/add" "$data")
    
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Record added successfully"
    else
        print_error "Failed to add record"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_update_record() {
    check_auth
    local zone="$1"
    local name="$2"
    local type="$3"
    local old_value="$4"
    local new_value="$5"
    local ttl="${6:-3600}"
    
    if [[ -z "$zone" || -z "$name" || -z "$type" || -z "$old_value" || -z "$new_value" ]]; then
        print_error "Usage: tdns-mgr.sh update-record <zone> <name> <type> <old_value> <new_value> [ttl]"
        exit 1
    fi
    
    print_info "Updating $type record: $name.$zone"
    
    local data="token=${DNS_TOKEN}&zone=${zone}&domain=${name}&type=${type}&ttl=${ttl}"
    
    case "$type" in
        A|AAAA)
            data="${data}&oldIpAddress=${old_value}&newIpAddress=${new_value}"
            ;;
        *)
            print_error "Update not implemented for type: $type"
            exit 1
            ;;
    esac
    
    local response=$(api_post "zones/records/update" "$data")
    
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Record updated successfully"
    else
        print_error "Failed to update record"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_delete_record() {
    check_auth
    local zone="$1"
    local name="$2"
    local type="$3"
    local value="$4"
    
    if [[ -z "$zone" || -z "$name" || -z "$type" ]]; then
        print_error "Usage: tdns-mgr.sh delete-record <zone> <name> <type> [value]"
        exit 1
    fi
    
    print_warning "Deleting $type record: $name.$zone"
    
    local data="token=${DNS_TOKEN}&zone=${zone}&domain=${name}&type=${type}"
    
    if [[ -n "$value" ]]; then
        case "$type" in
            A|AAAA)
                data="${data}&ipAddress=${value}"
                ;;
            CNAME)
                data="${data}&cname=${value}"
                ;;
        esac
    fi
    
    local response=$(api_post "zones/records/delete" "$data")
    
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Record deleted successfully"
    else
        print_error "Failed to delete record"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_import_records() {
    check_auth
    local file="$1"
    local create_ptr="false"
    
    # Check for --ptr argument
    if [[ "${2:-}" == "--ptr" ]]; then
        create_ptr="true"
    fi
    
    if [[ -z "$file" ]]; then
        print_error "Usage: tdns-mgr.sh import-records <file> [--ptr]"
        exit 1
    fi
    
    if [[ ! -f "$file" ]]; then
        echo "{\"New Records\": 0, \"Errors\": 1, \"Message\": \"File not found: $file\"}"
        exit 1
    fi
    
    print_info "Importing records from $file..."
    
    # Initialize counters and error logs
    local new_records=0
    local error_count=0
    local error_details=""
    local line_num=0
    
    # Bash/AWK CSV Parser
    # Handles basic CSV. For quoted fields with commas, this simple logic might split incorrectly
    # but covers standard usage. 
    
    while IFS= read -r line || [[ -n "$line" ]]; do
        ((line_num++))
        
        # Remove carriage return (Window compat)
        line="${line//$'\r'/}"
        
        # Skip comments and empty lines
        if [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]]; then
            continue
        fi
        
        # Skip header if it looks like header
        if [[ "$line_num" -eq 1 && "$line" =~ ^zone,name,type,value ]]; then
            continue
        fi
        
        # Parse CSV using awk to handle potential quoting better than straight read
        # This will convert CSV line to pipe-delimited values for safe reading by bash
        # A simple state-machine parser in awk to handle quotes
        parsed_line=$(echo "$line" | awk '{
            # Fallback for non-gawk (standard awk does not support FPAT)
            # We use a simpler strategy: replace "," within quotes with placeholder if needed
            # For this script, we assume values handled by simple split unless complex
            
            # Simple standard split for max compatibility as requested
            # We output using pipe delimiter which is safer for our read
            # If quotes exist, we strip them
            
            # This is a basic CSV parser that handles quoted comma fields
            $0=$0","; 
            while($0) {
                if ($0 ~ /^"[^"]*"|^[^",]*/) { 
                    match($0, /^"[^"]*"|^[^",]*/)
                    f=substr($0, RSTART, RLENGTH)
                    gsub(/^"|"$/, "", f) 
                    printf "%s|", f
                    $0=substr($0, RLENGTH+2)
                } else {
                    printf "|"
                    $0=substr($0, 2)
                }
            }
        }')
        
        IFS='|' read -r zone name type value _ <<< "$parsed_line"
        
        # Validation
        if [[ -z "$zone" || -z "$name" || -z "$type" || -z "$value" ]]; then
            continue
        fi
        
        # Prepare API data
        # Ensure domain is FQDN logic
        local domain_name="$name"
        if [[ "$name" == "@" ]]; then
            domain_name="$zone"
        elif [[ "$name" != *".$zone" ]]; then
            domain_name="$name.$zone"
        fi
        
        local data="token=${DNS_TOKEN}&zone=${zone}&domain=${domain_name}&type=${type}&ttl=3600"
        
        # PTR Logic
        if [[ "$create_ptr" == "true" && ("$type" == "A" || "$type" == "AAAA") ]]; then
            data="${data}&ptr=true&createPtrZone=true"
        fi
        
        case "$type" in
            A|AAAA)
                data="${data}&ipAddress=${value}"
                ;;
            CNAME)
                data="${data}&cname=${value}"
                ;;
            MX)
                data="${data}&exchange=${value}&preference=10"
                ;;
            TXT)
                data="${data}&text=${value}"
                ;;
            NS)
                data="${data}&nameServer=${value}"
                ;;
            PTR)
                data="${data}&ptrName=${value}"
                ;;
            *)
                ((error_count++))
                error_details="${error_details}Unsupported type '$type' for $name.$zone; "
                continue
                ;;
        esac
        
        # Call API directly
        local url="${DNS_PROTOCOL}://${DNS_SERVER}:${DNS_PORT}/api/zones/records/add"
        local response=""
        
        if [[ -n "$DNS_TOKEN" ]]; then
            response=$(curl -s -X POST "$url" -H "Authorization: Bearer $DNS_TOKEN" -d "$data")
        else
            response=$(curl -s -X POST "$url" -d "$data")
        fi
        
        if echo "$response" | grep -q '"status":"ok"'; then
            ((new_records++))
        else
            ((error_count++))
            local err_msg=$(echo "$response" | jq -r '.errorMessage' 2>/dev/null || echo "Unknown error")
            error_details="${error_details}Failed $name.$zone ($type): $err_msg; "
        fi
        
    done < "$file"

    # Construct JSON output
    local message="Success"
    if [[ $error_count -gt 0 ]]; then
        message="Completed with errors. Details: $error_details"
    fi
    
    # Sanitize message for JSON
    message=${message//\"/\\\"}
    
    echo "{
  \"New Records\": $new_records,
  \"Errors\": $error_count,
  \"Message\": \"$message\"
}"
}

################################################################################
# Server Management Functions
################################################################################

cmd_server_stats() {
    check_auth
    print_info "Fetching server statistics..."
    
    local response=$(api_post "dashboard/stats/get" "token=${DNS_TOKEN}")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

cmd_server_status() {
    print_info "Checking server status..."
    
    local check_url="${DNS_PROTOCOL}://${DNS_SERVER}:${DNS_PORT}"
    print_debug "Checking URL: $check_url"
    
    if curl -s -f "$check_url" > /dev/null 2>&1; then
        print_success "DNS Server is running at $check_url"
    else
        print_error "DNS Server is not accessible at $check_url"
        exit 1
    fi
}

cmd_flush_cache() {
    check_auth
    print_info "Flushing DNS cache..."
    
    local response=$(api_post "cache/flush" "token=${DNS_TOKEN}")
    
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Cache flushed successfully"
    else
        print_error "Failed to flush cache"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

################################################################################
# Query Functions
################################################################################

cmd_query() {
    check_auth
    local domain="$1"
    local type="${2:-A}"
    
    if [[ -z "$domain" ]]; then
        print_error "Usage: tdns-mgr.sh query <domain> [type]"
        exit 1
    fi
    
    print_info "Querying: $domain (Type: $type)"
    
    local response=$(api_post "dns/query" "token=${DNS_TOKEN}&domain=${domain}&type=${type}")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

################################################################################
# Cluster Management Functions
################################################################################

cmd_cluster_status() {
    check_auth
    local node="${1:-}"
    
    print_info "Fetching cluster status..."
    
    local data="token=${DNS_TOKEN}&includeServerIpAddresses=true"
    if [[ -n "$node" ]]; then
        data="${data}&node=${node}"
    fi
    
    local response=$(api_post "admin/cluster/state" "$data")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

cmd_cluster_init() {
    check_auth
    local domain="$1"
    local ip_addresses="$2"
    
    if [[ -z "$domain" || -z "$ip_addresses" ]]; then
        print_error "Usage: tdns-mgr.sh cluster-init <cluster_domain> <primary_ip_addresses>"
        print_info "Example: tdns-mgr.sh cluster-init cluster.local 192.168.1.10"
        exit 1
    fi
    
    print_info "Initializing cluster: $domain"
    
    local response=$(api_post "admin/cluster/init" "token=${DNS_TOKEN}&clusterDomain=${domain}&primaryNodeIpAddresses=${ip_addresses}")
    
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Cluster initialized successfully"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    else
        print_error "Failed to initialize cluster"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_cluster_join() {
    check_auth
    local primary_url="$1"
    local ip_addresses="$2"
    local primary_user="$3"
    local primary_pass="$4"
    local primary_ip="${5:-}"
    local ignore_cert="${6:-true}"
    
    if [[ -z "$primary_url" || -z "$ip_addresses" || -z "$primary_user" ]]; then
        print_error "Usage: tdns-mgr.sh cluster-join <primary_url> <my_ip_addresses> <primary_user> [primary_pass] [primary_ip] [ignore_cert]"
        print_info "Example: tdns-mgr.sh cluster-join https://primary:5380 192.168.1.11 admin"
        exit 1
    fi
    
    if [[ -z "$primary_pass" ]]; then
        read -sp "Primary Node Password: " primary_pass
        echo "" >&2
    fi
    
    print_info "Joining cluster at $primary_url..."
    
    local data="token=${DNS_TOKEN}&primaryNodeUrl=${primary_url}&secondaryNodeIpAddresses=${ip_addresses}&primaryNodeUsername=${primary_user}&primaryNodePassword=${primary_pass}&ignoreCertificateErrors=${ignore_cert}"
    
    if [[ -n "$primary_ip" ]]; then
        data="${data}&primaryNodeIpAddress=${primary_ip}"
    fi
    
    local response=$(api_post "admin/cluster/initJoin" "$data")
    
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Joined cluster successfully"
    else
        print_error "Failed to join cluster"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_cluster_leave() {
    check_auth
    local force="${1:-false}"
    
    print_warning "Leaving cluster..."
    if [[ "$force" == "false" ]]; then
         read -p "Are you sure? (yes/no): " confirm
         if [[ "$confirm" != "yes" ]]; then
             print_info "Cancelled"
             exit 0
         fi
    fi
    
    local response=$(api_post "admin/cluster/secondary/leave" "token=${DNS_TOKEN}&forceLeave=${force}")
    
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Left cluster successfully"
    else
        print_error "Failed to leave cluster"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_cluster_promote() {
    check_auth
    local force="${1:-false}"
    
    print_warning "Promoting this node to Primary..."
    read -p "Are you sure? (yes/no): " confirm
    if [[ "$confirm" != "yes" ]]; then
         print_info "Cancelled"
         exit 0
    fi
    
    local response=$(api_post "admin/cluster/secondary/promote" "token=${DNS_TOKEN}&forceDeletePrimary=${force}")
    
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Node promoted to Primary successfully"
    else
        print_error "Failed to promote node"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_cluster_resync() {
    check_auth
    print_info "Resyncing with primary..."
    
    local response=$(api_post "admin/cluster/secondary/resync" "token=${DNS_TOKEN}")
    
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Resync triggered successfully"
    else
        print_error "Failed to trigger resync"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

################################################################################
# Administration Functions
################################################################################

cmd_admin_user_list() {
    check_auth
    print_info "Listing users..."
    
    local response=$(api_post "admin/users/list" "token=${DNS_TOKEN}")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

cmd_admin_user_create() {
    check_auth
    local user="$1"
    local pass="$2"
    local display_name="${3:-}"
    
    if [[ -z "$user" || -z "$pass" ]]; then
        print_error "Usage: tdns-mgr.sh admin-user-create <username> <password> [display_name]"
        exit 1
    fi
    
    print_info "Creating user: $user"
    local data="token=${DNS_TOKEN}&user=${user}&pass=${pass}"
    if [[ -n "$display_name" ]]; then
        data="${data}&displayName=${display_name}"
    fi
    
    local response=$(api_post "admin/users/create" "$data")
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "User created successfully"
    else
        print_error "Failed to create user"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_admin_user_delete() {
    check_auth
    local user="$1"
    
    if [[ -z "$user" ]]; then
        print_error "Usage: tdns-mgr.sh admin-user-delete <username>"
        exit 1
    fi
    
    print_warning "Deleting user: $user"
    read -p "Are you sure? (yes/no): " confirm
    if [[ "$confirm" != "yes" ]]; then
        print_info "Cancelled"
        exit 0
    fi
    
    local response=$(api_post "admin/users/delete" "token=${DNS_TOKEN}&user=${user}")
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "User deleted successfully"
    else
        print_error "Failed to delete user"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_admin_group_list() {
    check_auth
    print_info "Listing groups..."
    local response=$(api_post "admin/groups/list" "token=${DNS_TOKEN}")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

cmd_admin_group_create() {
    check_auth
    local group="$1"
    local description="${2:-}"
    
    if [[ -z "$group" ]]; then
        print_error "Usage: tdns-mgr.sh admin-group-create <group_name> [description]"
        exit 1
    fi
    
    print_info "Creating group: $group"
    local data="token=${DNS_TOKEN}&group=${group}"
    if [[ -n "$description" ]]; then
        data="${data}&description=${description}"
    fi
    
    local response=$(api_post "admin/groups/create" "$data")
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Group created successfully"
    else
        print_error "Failed to create group"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_admin_group_delete() {
    check_auth
    local group="$1"
    
    if [[ -z "$group" ]]; then
        print_error "Usage: tdns-mgr.sh admin-group-delete <group_name>"
        exit 1
    fi
    
    print_warning "Deleting group: $group"
    read -p "Are you sure? (yes/no): " confirm
    if [[ "$confirm" != "yes" ]]; then
        print_info "Cancelled"
        exit 0
    fi
    
    local response=$(api_post "admin/groups/delete" "token=${DNS_TOKEN}&group=${group}")
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Group deleted successfully"
    else
        print_error "Failed to delete group"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_admin_perm_list() {
    check_auth
    print_info "Listing permissions..."
    local response=$(api_post "admin/permissions/list" "token=${DNS_TOKEN}")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

cmd_admin_session_list() {
    check_auth
    print_info "Listing sessions..."
    local response=$(api_post "admin/sessions/list" "token=${DNS_TOKEN}")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

cmd_admin_session_delete() {
    check_auth
    local partial_token="$1"
    
    if [[ -z "$partial_token" ]]; then
        print_error "Usage: tdns-mgr.sh admin-session-delete <partial_token>"
        exit 1
    fi
    
    print_info "Deleting session: $partial_token"
    local response=$(api_post "admin/sessions/delete" "token=${DNS_TOKEN}&partialToken=${partial_token}")
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Session deleted successfully"
    else
        print_error "Failed to delete session"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_admin_token_create() {
    check_auth
    local user="$1"
    local name="$2"
    
    if [[ -z "$user" || -z "$name" ]]; then
        print_error "Usage: tdns-mgr.sh admin-token-create <user> <token_name>"
        exit 1
    fi
    
    print_info "Creating token '$name' for user '$user'..."
    local response=$(api_post "admin/sessions/createToken" "token=${DNS_TOKEN}&user=${user}&tokenName=${name}")
    if echo "$response" | grep -q '"status":"ok"'; then
        local token=$(echo "$response" | jq -r '.response.token' 2>/dev/null)
        print_success "Token created: $token"
    else
        print_error "Failed to create token"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

################################################################################
# DHCP Management Functions
################################################################################

cmd_dhcp_scope_list() {
    check_auth
    print_info "Listing DHCP scopes..."
    local response=$(api_post "dhcp/scopes/list" "token=${DNS_TOKEN}")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

cmd_dhcp_scope_get() {
    check_auth
    local name="$1"
    
    if [[ -z "$name" ]]; then
        print_error "Usage: tdns-mgr.sh dhcp-scope-get <scope_name>"
        exit 1
    fi
    
    print_info "Getting DHCP scope: $name"
    local response=$(api_post "dhcp/scopes/get" "token=${DNS_TOKEN}&name=${name}")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

cmd_dhcp_scope_set() {
    check_auth
    local name="$1"
    local start_ip="$2"
    local end_ip="$3"
    local subnet_mask="$4"
    shift 4  # Remove first 4 arguments
    local options="$*"  # Capture all remaining arguments
    
    if [[ -z "$name" || -z "$start_ip" || -z "$end_ip" || -z "$subnet_mask" ]]; then
        print_error "Usage: tdns-mgr.sh dhcp-scope-set <name> <start_ip> <end_ip> <subnet_mask> [options...]"
        print_info "Options example: leaseTimeDays=7 gateway=192.168.1.1"
        exit 1
    fi
    
    print_info "Setting DHCP scope: $name"
    local data="token=${DNS_TOKEN}&name=${name}&startingAddress=${start_ip}&endingAddress=${end_ip}&subnetMask=${subnet_mask}"
    
    # Append any additional options directly to data
    for opt in $options; do
        data="${data}&${opt}"
    done
    
    local response=$(api_post "dhcp/scopes/set" "$data")
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "DHCP scope set successfully"
    else
        print_error "Failed to set DHCP scope"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_dhcp_scope_enable() {
    check_auth
    local name="$1"
    
    if [[ -z "$name" ]]; then
        print_error "Usage: tdns-mgr.sh dhcp-scope-enable <scope_name>"
        exit 1
    fi
    
    print_info "Enabling DHCP scope: $name"
    local response=$(api_post "dhcp/scopes/enable" "token=${DNS_TOKEN}&name=${name}")
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "DHCP scope enabled"
    else
        print_error "Failed to enable DHCP scope"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_dhcp_scope_disable() {
    check_auth
    local name="$1"
    
    if [[ -z "$name" ]]; then
        print_error "Usage: tdns-mgr.sh dhcp-scope-disable <scope_name>"
        exit 1
    fi
    
    print_info "Disabling DHCP scope: $name"
    local response=$(api_post "dhcp/scopes/disable" "token=${DNS_TOKEN}&name=${name}")
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "DHCP scope disabled"
    else
        print_error "Failed to disable DHCP scope"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_dhcp_scope_delete() {
    check_auth
    local name="$1"
    
    if [[ -z "$name" ]]; then
        print_error "Usage: tdns-mgr.sh dhcp-scope-delete <scope_name>"
        exit 1
    fi
    
    print_warning "Deleting DHCP scope: $name"
    read -p "Are you sure? (yes/no): " confirm
    if [[ "$confirm" != "yes" ]]; then
        print_info "Cancelled"
        exit 0
    fi
    
    local response=$(api_post "dhcp/scopes/delete" "token=${DNS_TOKEN}&name=${name}")
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "DHCP scope deleted"
    else
        print_error "Failed to delete DHCP scope"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_dhcp_lease_list() {
    check_auth
    print_info "Listing DHCP leases..."
    local response=$(api_post "dhcp/leases/list" "token=${DNS_TOKEN}")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

cmd_dhcp_lease_remove() {
    check_auth
    local scope="$1"
    local mac="$2"
    
    if [[ -z "$scope" || -z "$mac" ]]; then
        print_error "Usage: tdns-mgr.sh dhcp-lease-remove <scope_name> <mac_address>"
        exit 1
    fi
    
    print_info "Removing lease for $mac in $scope..."
    local response=$(api_post "dhcp/leases/remove" "token=${DNS_TOKEN}&name=${scope}&hardwareAddress=${mac}")
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Lease removed successfully"
    else
        print_error "Failed to remove lease"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_dhcp_lease_convert() {
    check_auth
    local scope="$1"
    local mac="$2"
    local type="$3" # Reserved or Dynamic
    
    if [[ -z "$scope" || -z "$mac" || -z "$type" ]]; then
        print_error "Usage: tdns-mgr.sh dhcp-lease-convert <scope_name> <mac_address> <Reserved|Dynamic>"
        exit 1
    fi
    
    local endpoint=""
    if [[ "${type,,}" == "reserved" ]]; then
        endpoint="dhcp/leases/convertToReserved"
    elif [[ "${type,,}" == "dynamic" ]]; then
        endpoint="dhcp/leases/convertToDynamic"
    else
        print_error "Invalid type: $type. Must be Reserved or Dynamic."
        exit 1
    fi
    
    print_info "Converting lease for $mac to $type..."
    local response=$(api_post "$endpoint" "token=${DNS_TOKEN}&name=${scope}&hardwareAddress=${mac}")
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Lease converted successfully"
    else
        print_error "Failed to convert lease"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

################################################################################
# Apps Management Functions
################################################################################

cmd_app_list() {
    check_auth
    local type="${1:-installed}"
    
    if [[ "$type" == "store" ]]; then
        print_info "Listing store apps..."
        local response=$(api_post "apps/listStoreApps" "token=${DNS_TOKEN}")
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    else
        print_info "Listing installed apps..."
        local response=$(api_post "apps/list" "token=${DNS_TOKEN}")
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_app_install() {
    check_auth
    local name="$1"
    local url="${2:-}"
    
    if [[ -z "$name" ]]; then
        print_error "Usage: tdns-mgr.sh app-install <app_name> [url_or_file]"
        print_info "If url_or_file is a URL (starts with https://), it downloads and installs."
        print_info "If url_or_file is a file path, it uploads and installs."
        print_info "If omitted, it tries to install from store if supported (not directly supported by simple name API currently, usually requires URL)."
        exit 1
    fi
    
    if [[ -z "$url" ]]; then
        print_error "Please provide a URL or file path for the app."
        exit 1
    fi
    
    if [[ "$url" =~ ^https:// ]]; then
        print_info "Downloading and installing app: $name from $url"
        local response=$(api_post "apps/downloadAndInstall" "token=${DNS_TOKEN}&name=${name}&url=${url}")
        if echo "$response" | grep -q '"status":"ok"'; then
            print_success "App installed successfully"
        else
            print_error "Failed to install app"
            echo "$response" | jq '.' 2>/dev/null || echo "$response"
        fi
    elif [[ -f "$url" ]]; then
        print_info "Uploading and installing app: $name from $url"
        local api_url="${DNS_PROTOCOL}://${DNS_SERVER}:${DNS_PORT}/api/apps/install?token=${DNS_TOKEN}&name=${name}"
        local response=$(curl -s -X POST "$api_url" -F "file=@$url")
        if echo "$response" | grep -q '"status":"ok"'; then
            print_success "App uploaded and installed successfully"
        else
            print_error "Failed to install app"
            echo "$response" | jq '.' 2>/dev/null || echo "$response"
        fi
    else
        print_error "File not found or invalid URL: $url"
        exit 1
    fi
}

cmd_app_uninstall() {
    check_auth
    local name="$1"
    
    if [[ -z "$name" ]]; then
        print_error "Usage: tdns-mgr.sh app-uninstall <app_name>"
        exit 1
    fi
    
    print_warning "Uninstalling app: $name"
    read -p "Are you sure? (yes/no): " confirm
    if [[ "$confirm" != "yes" ]]; then
        print_info "Cancelled"
        exit 0
    fi
    
    local response=$(api_post "apps/uninstall" "token=${DNS_TOKEN}&name=${name}")
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "App uninstalled successfully"
    else
        print_error "Failed to uninstall app"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_app_config_get() {
    check_auth
    local name="$1"
    
    if [[ -z "$name" ]]; then
        print_error "Usage: tdns-mgr.sh app-config-get <app_name>"
        exit 1
    fi
    
    print_info "Getting config for app: $name"
    local response=$(api_post "apps/config/get" "token=${DNS_TOKEN}&name=${name}")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

cmd_app_config_set() {
    check_auth
    local name="$1"
    local config="$2"
    
    if [[ -z "$name" || -z "$config" ]]; then
        print_error "Usage: tdns-mgr.sh app-config-set <app_name> <config_string>"
        exit 1
    fi
    
    print_info "Setting config for app: $name"
    local response=$(api_post "apps/config/set" "token=${DNS_TOKEN}&name=${name}&config=${config}")
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "App config set successfully"
    else
        print_error "Failed to set app config"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

################################################################################
# Blocked & Allowed Zones Functions
################################################################################

cmd_blocked_list() {
    check_auth
    local domain="${1:-}"
    
    print_info "Listing blocked zones..."
    local data="token=${DNS_TOKEN}"
    if [[ -n "$domain" ]]; then
        data="${data}&domain=${domain}"
    fi
    
    local response=$(api_post "blocked/list" "$data")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

cmd_blocked_add() {
    check_auth
    local domain="$1"
    
    if [[ -z "$domain" ]]; then
        print_error "Usage: tdns-mgr.sh blocked-add <domain>"
        exit 1
    fi
    
    print_info "Blocking domain: $domain"
    local response=$(api_post "blocked/add" "token=${DNS_TOKEN}&domain=${domain}")
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Domain blocked successfully"
    else
        print_error "Failed to block domain"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_blocked_delete() {
    check_auth
    local domain="$1"
    
    if [[ -z "$domain" ]]; then
        print_error "Usage: tdns-mgr.sh blocked-delete <domain>"
        exit 1
    fi
    
    print_warning "Unblocking domain: $domain"
    local response=$(api_post "blocked/delete" "token=${DNS_TOKEN}&domain=${domain}")
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Domain unblocked successfully"
    else
        print_error "Failed to unblock domain"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_blocked_flush() {
    check_auth
    print_warning "Flushing ALL blocked zones..."
    read -p "Are you sure? (yes/no): " confirm
    if [[ "$confirm" != "yes" ]]; then
        print_info "Cancelled"
        exit 0
    fi
    
    local response=$(api_post "blocked/flush" "token=${DNS_TOKEN}")
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Blocked zones flushed successfully"
    else
        print_error "Failed to flush blocked zones"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_allowed_list() {
    check_auth
    local domain="${1:-}"
    
    print_info "Listing allowed zones..."
    local data="token=${DNS_TOKEN}"
    if [[ -n "$domain" ]]; then
        data="${data}&domain=${domain}"
    fi
    
    local response=$(api_post "allowed/list" "$data")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

cmd_allowed_add() {
    check_auth
    local domain="$1"
    
    if [[ -z "$domain" ]]; then
        print_error "Usage: tdns-mgr.sh allowed-add <domain>"
        exit 1
    fi
    
    print_info "Allowing domain: $domain"
    local response=$(api_post "allowed/add" "token=${DNS_TOKEN}&domain=${domain}")
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Domain allowed successfully"
    else
        print_error "Failed to allow domain"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_allowed_delete() {
    check_auth
    local domain="$1"
    
    if [[ -z "$domain" ]]; then
        print_error "Usage: tdns-mgr.sh allowed-delete <domain>"
        exit 1
    fi
    
    print_warning "Removing allowed domain: $domain"
    local response=$(api_post "allowed/delete" "token=${DNS_TOKEN}&domain=${domain}")
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Allowed domain removed successfully"
    else
        print_error "Failed to remove allowed domain"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_allowed_flush() {
    check_auth
    print_warning "Flushing ALL allowed zones..."
    read -p "Are you sure? (yes/no): " confirm
    if [[ "$confirm" != "yes" ]]; then
        print_info "Cancelled"
        exit 0
    fi
    
    local response=$(api_post "allowed/flush" "token=${DNS_TOKEN}")
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Allowed zones flushed successfully"
    else
        print_error "Failed to flush allowed zones"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_blocklists_update() {
    check_auth
    print_info "Forcing update of block lists..."
    local response=$(api_post "settings/forceUpdateBlockLists" "token=${DNS_TOKEN}")
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Block lists update triggered"
    else
        print_error "Failed to update block lists"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

################################################################################
# Logging & Stats Functions
################################################################################

cmd_log_list() {
    check_auth
    print_info "Listing log files..."
    local response=$(api_post "logs/list" "token=${DNS_TOKEN}")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

cmd_log_download() {
    check_auth
    local file_name="$1"
    local limit="${2:-0}"
    local out_file="${3:-$file_name.log}"
    
    if [[ -z "$file_name" ]]; then
        print_error "Usage: tdns-mgr.sh log-download <log_filename> [limit_mb] [output_file]"
        exit 1
    fi
    
    print_info "Downloading log file: $file_name (Limit: ${limit}MB)"
    
    local url="${DNS_PROTOCOL}://${DNS_SERVER}:${DNS_PORT}/api/logs/download?token=${DNS_TOKEN}&fileName=${file_name}&limit=${limit}"
    
    if curl -s -f "$url" -o "$out_file"; then
        print_success "Log downloaded to $out_file"
    else
        print_error "Failed to download log"
        exit 1
    fi
}

cmd_log_query() {
    check_auth
    local app_name="$1"
    local class_path="$2"
    shift 2  # Remove first 2 arguments
    local options="$*"  # Capture all remaining arguments
    
    if [[ -z "$app_name" || -z "$class_path" ]]; then
        print_error "Usage: tdns-mgr.sh log-query <app_name> <class_path> [options...]"
        print_info "Common Options: pageNumber=1 entriesPerPage=10 clientIpAddress=1.2.3.4"
        exit 1
    fi
    
    print_info "Querying logs for $app_name..."
    local data="token=${DNS_TOKEN}&name=${app_name}&classPath=${class_path}"
    
    for opt in $options; do
        data="${data}&${opt}"
    done
    
    local response=$(api_post "logs/query" "$data")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

cmd_stats_top() {
    check_auth
    local type="${1:-TopClients}"
    local duration="${2:-LastHour}"
    local limit="${3:-10}"
    
    print_info "Fetching top stats ($type, $duration)..."
    
    local data="token=${DNS_TOKEN}&statsType=${type}&type=${duration}&limit=${limit}"
    
    local response=$(api_post "dashboard/stats/getTop" "$data")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

################################################################################
# DNSSEC Management Functions
################################################################################

cmd_dnssec_sign() {
    check_auth
    local zone="$1"
    local algorithm="${2:-ECDSA}"
    local curve="${3:-P256}"
    
    if [[ -z "$zone" ]]; then
        print_error "Usage: tdns-mgr.sh dnssec-sign <zone> [algorithm] [curve]"
        print_info "Algorithms: RSA, ECDSA (default), EDDSA"
        print_info "Curves: P256 (default), P384, ED25519, ED448"
        exit 1
    fi
    
    print_info "Signing zone: $zone (Algo: $algorithm, Curve: $curve)"
    
    local data="token=${DNS_TOKEN}&zone=${zone}&algorithm=${algorithm}&curve=${curve}"
    
    # Add defaults for other params if needed, or expose them as args
    
    local response=$(api_post "zones/dnssec/sign" "$data")
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Zone signed successfully"
    else
        print_error "Failed to sign zone"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_dnssec_unsign() {
    check_auth
    local zone="$1"
    
    if [[ -z "$zone" ]]; then
        print_error "Usage: tdns-mgr.sh dnssec-unsign <zone>"
        exit 1
    fi
    
    print_warning "Unsigning zone: $zone"
    read -p "Are you sure? (yes/no): " confirm
    if [[ "$confirm" != "yes" ]]; then
        print_info "Cancelled"
        exit 0
    fi
    
    local response=$(api_post "zones/dnssec/unsign" "token=${DNS_TOKEN}&zone=${zone}")
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Zone unsigned successfully"
    else
        print_error "Failed to unsign zone"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_dnssec_status() {
    check_auth
    local zone="$1"
    
    if [[ -z "$zone" ]]; then
        print_error "Usage: tdns-mgr.sh dnssec-status <zone>"
        exit 1
    fi
    
    print_info "Getting DNSSEC status for: $zone"
    local response=$(api_post "zones/dnssec/viewDS" "token=${DNS_TOKEN}&zone=${zone}")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

################################################################################
# Settings & Advanced Zone Functions
################################################################################

cmd_settings_get() {
    check_auth
    print_info "Fetching server settings..."
    local response=$(api_post "settings/get" "token=${DNS_TOKEN}")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

cmd_settings_set() {
    check_auth
    local options="$*"
    
    if [[ -z "$options" ]]; then
        print_error "Usage: tdns-mgr.sh settings-set [option=value...]"
        print_info "Example: tdns-mgr.sh settings-set allowRecursion=true logQueries=false"
        exit 1
    fi
    
    print_info "Updating settings..."
    
    local data="token=${DNS_TOKEN}"
    for opt in $options; do
        data="${data}&${opt}"
    done
    
    local response=$(api_post "settings/set" "$data")
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Settings updated successfully"
    else
        print_error "Failed to update settings"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_zone_options_get() {
    check_auth
    local zone="$1"
    
    if [[ -z "$zone" ]]; then
        print_error "Usage: tdns-mgr.sh zone-options-get <zone>"
        exit 1
    fi
    
    print_info "Getting options for zone: $zone"
    local response=$(api_post "zones/options/get" "token=${DNS_TOKEN}&zone=${zone}")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

cmd_zone_options_set() {
    check_auth
    local zone="$1"
    shift  # Remove first argument
    local options="$*"  # Capture all remaining arguments
    
    if [[ -z "$zone" || -z "$options" ]]; then
        print_error "Usage: tdns-mgr.sh zone-options-set <zone> [option=value...]"
        exit 1
    fi
    
    print_info "Setting options for zone: $zone"
    local data="token=${DNS_TOKEN}&zone=${zone}"
    for opt in $options; do
        data="${data}&${opt}"
    done
    
    local response=$(api_post "zones/options/set" "$data")
    if echo "$response" | grep -q '"status":"ok"'; then
        print_success "Zone options updated successfully"
    else
        print_error "Failed to update zone options"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
}

cmd_catalog_list() {
    check_auth
    print_info "Listing catalog zones..."
    local response=$(api_post "zones/catalogs/list" "token=${DNS_TOKEN}")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

################################################################################
# DNS Client Functions
################################################################################

cmd_client_resolve() {
    check_auth
    local domain="$1"
    local type="${2:-A}"
    local server="${3:-recursive-resolver}"
    local protocol="${4:-UDP}"
    shift 4 2>/dev/null || shift $#  # Remove first 4 arguments if possible
    local options="$*"  # Capture all remaining arguments
    
    if [[ -z "$domain" ]]; then
        print_error "Usage: tdns-mgr.sh client-resolve <domain> [type] [server] [protocol] [options...]"
        print_info "Server: recursive-resolver (default), system-dns, or IP/Hostname"
        print_info "Protocol: UDP (default), TCP, TLS, HTTPS, QUIC"
        exit 1
    fi
    
    print_info "Resolving $domain ($type) via $server ($protocol)..."
    local data="token=${DNS_TOKEN}&domain=${domain}&type=${type}&server=${server}&protocol=${protocol}"
    
    for opt in $options; do
        data="${data}&${opt}"
    done
    
    local response=$(api_post "dnsClient/resolve" "$data")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

################################################################################
# Configuration Functions
################################################################################

cmd_config() {
    local action="${1:-show}"
    
    case "$action" in
        show)
            print_info "Current configuration:"
            echo "  Server: ${DNS_SERVER}"
            echo "  Port: ${DNS_PORT}"
            echo "  Protocol: ${DNS_PROTOCOL}"
            echo "  User: ${DNS_USER}"
            echo "  Token: ${DNS_TOKEN:+[SET]}"
            echo "  Config file: ${CONFIG_FILE}"
            ;;
        set)
            local key="$2"
            local value="$3"
            
            case "$key" in
                server)
                    DNS_SERVER="$value"
                    save_config
                    print_success "Server set to: $value"
                    ;;
                port)
                    DNS_PORT="$value"
                    save_config
                    print_success "Port set to: $value"
                    ;;
                protocol)
                    if [[ "$value" != "http" && "$value" != "https" ]]; then
                        print_error "Protocol must be 'http' or 'https'"
                        exit 1
                    fi
                    DNS_PROTOCOL="$value"
                    save_config
                    print_success "Protocol set to: $value"
                    ;;
                user)
                    DNS_USER="$value"
                    save_config
                    print_success "User set to: $value"
                    ;;
                *)
                    print_error "Unknown config key: $key"
                    print_info "Valid keys: server, port, protocol, user"
                    exit 1
                    ;;
            esac
            ;;
        *)
            print_error "Unknown config action: $action"
            print_info "Valid actions: show, set"
            exit 1
            ;;
    esac
}

################################################################################
# Menu Function
################################################################################

show_summary() {
    print_header
    
    echo -e "USAGE:"
    echo -e "    tdns-mgr.sh [options] [command] [args]"
    echo -e "    tdns-mgr.sh --help <topic>        Show detailed help for a specific topic"
    echo -e "    tdns-mgr.sh --help --verbose      Show all available commands"
    echo -e ""
    echo -e "OPTIONS:"
    echo -e "    -q, --quiet, --silent           Suppress informational output (useful for scripting)"
    echo -e "    -h, --help [topic]              Show help (optionally for a specific topic)"
    echo -e "    -v, --version                   Show version"
    echo -e "    --verbose                       Show verbose help with all commands"
    echo -e "    --debug                         Show debug information (API calls, responses, etc.)"
    echo -e ""
    echo -e "${BLUE}AVAILABLE HELP TOPICS:${NC}"
    echo -e "    Authentication                  Login, logout, password, updates, config"
    echo -e "    DNS                             Zones, records, import/export, queries"
    echo -e "    Cluster                         Cluster initialization, joining, syncing"
    echo -e "    Administration                  Users, groups, permissions, sessions, tokens"
    echo -e "    DHCP                            DHCP scopes, leases, reservations"
    echo -e "    Apps                            DNS Apps installation and configuration"
    echo -e "    Blocked                         Blocked and allowed zones management"
    echo -e "    Logging                         Log queries, downloads, and statistics"
    echo -e "    DNSSEC                          DNSSEC signing and management"
    echo -e "    Settings                        Server and zone configuration"
    echo -e "    Client                          DNS client resolution tool"
    echo -e ""
    echo -e "${YELLOW}EXAMPLES:${NC}"
    echo -e "    ${GREEN}# Show help for a specific topic${NC}"
    echo -e "    tdns-mgr.sh --help Authentication"
    echo -e "    tdns-mgr.sh --help DNS"
    echo -e "    tdns-mgr.sh --help Cluster"
    echo -e ""
    echo -e "    ${GREEN}# Show all commands (verbose)${NC}"
    echo -e "    tdns-mgr.sh --help --verbose"
    echo -e ""
    echo -e "    ${GREEN}# Quick command examples${NC}"
    echo -e "    tdns-mgr.sh login"
    echo -e "    tdns-mgr.sh create-zone example.com Primary"
    echo -e "    tdns-mgr.sh add-record example.com www A 192.168.1.100"
    echo -e ""
    echo -e "${CYAN}ENVIRONMENT VARIABLES:${NC}"
    echo -e "    DNS_SERVER      DNS server hostname/IP (default: localhost)"
    echo -e "    DNS_PORT        DNS server port (default: 5380)"
    echo -e "    DNS_PROTOCOL    Protocol to use: http or https (default: https)"
    echo -e "    DNS_USER        Username (default: admin)"
    echo -e "    DNS_PASS        Password (for non-interactive login)"
    echo -e "    DNS_TOKEN       API token (set after login)"
    echo -e ""
    echo -e "${CYAN}DOCUMENTATION:${NC}"
    echo -e "    Config checked: CLI args, ~/.config/tdns-mgr/.tdns-mgr.conf, /etc/tdns-mgr/.tdns-mgr.conf, script/.tdns-mgr.conf"
    echo -e "    Full examples: EXAMPLES.md"
    echo -e "    API Reference: https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md"
    echo -e ""
}

show_help_authentication() {
    echo -e ""
    echo -e "${BLUE}AUTHENTICATION COMMANDS:${NC}"
    echo -e "    login                           Login to DNS server"
    echo -e "    logout                          Logout from DNS server"
    echo -e "    change-password <new_pass>      Change user password"
    echo -e "    check-update                    Check for DNS server updates"
    echo -e "    config [show|set]               Show or set configuration"
    echo -e ""
    echo -e "${YELLOW}EXAMPLES:${NC}"
    echo -e "    ${GREEN}# Interactive login${NC}"
    echo -e "    tdns-mgr.sh login"
    echo -e ""
    echo -e "    ${GREEN}# Non-interactive login using environment variable${NC}"
    echo -e "    DNS_PASS=mypassword tdns-mgr.sh login"
    echo -e ""
    echo -e "    ${GREEN}# Change password${NC}"
    echo -e "    tdns-mgr.sh change-password newStrongPassword123"
    echo -e ""
    echo -e "    ${GREEN}# Check for server updates${NC}"
    echo -e "    tdns-mgr.sh check-update"
    echo -e ""
    echo -e "    ${GREEN}# Show current configuration${NC}"
    echo -e "    tdns-mgr.sh config show"
    echo -e ""
}

show_help_dns() {
    echo -e ""
    echo -e "${BLUE}DNS (ZONES & RECORDS) COMMANDS:${NC}"
    echo -e "    list-zones                      List all DNS zones"
    echo -e "    create-zone <domain> [type]     Create zone (Primary, Secondary, Stub, Forwarder)"
    echo -e "    delete-zone <domain>            Delete a zone"
    echo -e "    enable-zone <domain>            Enable a zone"
    echo -e "    disable-zone <domain>           Disable a zone"
    echo -e "    export-zone <domain> [file]     Export zone (BIND format)"
    echo -e "    import-zone <domain> <file>     Import zone (BIND format)"
    echo -e "    export-zones [file]             Export all zones (zip)"
    echo -e "    import-zones <file>             Import all zones (zip)"
    echo -e "    "
    echo -e "    list-records <zone>             List all records in a zone"
    echo -e "    add-record <zone> <name> <type> <value> [ttl] [--ptr]"
    echo -e "                                    Add DNS record (A, AAAA, CNAME, MX, TXT, NS, PTR, etc.)"
    echo -e "    update-record <zone> <name> <type> <old> <new> [ttl]"
    echo -e "                                    Update DNS record"
    echo -e "    delete-record <zone> <name> <type> [value]"
    echo -e "                                    Delete DNS record"
    echo -e "    import-records <file> [--ptr]   Import records from CSV file"
    echo -e "    "
    echo -e "    server-status                   Check if server is running"
    echo -e "    server-stats                    Get server statistics"
    echo -e "    flush-cache                     Flush DNS cache"
    echo -e "    query <domain> [type]           Query DNS records"
    echo -e ""
    echo -e "${YELLOW}EXAMPLES:${NC}"
    echo -e "    ${GREEN}# Create a primary zone${NC}"
    echo -e "    tdns-mgr.sh create-zone example.com Primary"
    echo -e ""
    echo -e "    ${GREEN}# Add an A record${NC}"
    echo -e "    tdns-mgr.sh add-record example.com www A 192.168.1.100"
    echo -e ""
    echo -e "    ${GREEN}# Add A record with automatic PTR${NC}"
    echo -e "    tdns-mgr.sh add-record example.com mail A 192.168.1.50 3600 --ptr"
    echo -e ""
    echo -e "    ${GREEN}# Import records from CSV${NC}"
    echo -e "    tdns-mgr.sh import-records dns-records.csv"
    echo -e ""
    echo -e "    ${GREEN}# Export all zones${NC}"
    echo -e "    tdns-mgr.sh export-zones backup-\$(date +%Y%m%d).zip"
    echo -e ""
}

show_help_cluster() {
    echo -e ""
    echo -e "${BLUE}CLUSTER MANAGEMENT COMMANDS:${NC}"
    echo -e "    cluster-status [node]           Get cluster status"
    echo -e "    cluster-init <domain> <ip>      Initialize a new cluster"
    echo -e "    cluster-join <url> <ip> <user>  Join an existing cluster"
    echo -e "    cluster-leave [force]           Leave the cluster"
    echo -e "    cluster-promote [force]         Promote to primary node"
    echo -e "    cluster-resync                  Force resync with primary"
    echo -e ""
    echo -e "${YELLOW}EXAMPLES:${NC}"
    echo -e "    ${GREEN}# Initialize a new cluster${NC}"
    echo -e "    tdns-mgr.sh cluster-init mycluster.local 192.168.1.10"
    echo -e ""
    echo -e "    ${GREEN}# Join an existing cluster${NC}"
    echo -e "    tdns-mgr.sh cluster-join https://192.168.1.10:5380 192.168.1.11 admin"
    echo -e ""
    echo -e "    ${GREEN}# Check cluster status${NC}"
    echo -e "    tdns-mgr.sh cluster-status"
    echo -e ""
    echo -e "    ${GREEN}# Force resync with primary${NC}"
    echo -e "    tdns-mgr.sh cluster-resync"
    echo -e ""
}

show_help_administration() {
    echo -e ""
    echo -e "${BLUE}ADMINISTRATION (USERS, GROUPS, PERMISSIONS) COMMANDS:${NC}"
    echo -e "    admin-user-list                 List users"
    echo -e "    admin-user-create <user> <pass> [name]"
    echo -e "                                    Create a user"
    echo -e "    admin-user-delete <user>        Delete a user"
    echo -e "    admin-group-list                List groups"
    echo -e "    admin-group-create <group> [desc]"
    echo -e "                                    Create a group"
    echo -e "    admin-group-delete <group>      Delete a group"
    echo -e "    admin-perm-list                 List permissions"
    echo -e "    admin-session-list              List active sessions"
    echo -e "    admin-session-delete <token>    Delete a session"
    echo -e "    admin-token-create <user> <name>"
    echo -e "                                    Create API token"
    echo -e ""
    echo -e "${YELLOW}EXAMPLES:${NC}"
    echo -e "    ${GREEN}# Create a new user${NC}"
    echo -e "    tdns-mgr.sh admin-user-create john SecurePass123 \"John Doe\""
    echo -e ""
    echo -e "    ${GREEN}# List all users${NC}"
    echo -e "    tdns-mgr.sh admin-user-list"
    echo -e ""
    echo -e "    ${GREEN}# Create a group${NC}"
    echo -e "    tdns-mgr.sh admin-group-create operators \"DNS Operators\""
    echo -e ""
    echo -e "    ${GREEN}# Create an API token${NC}"
    echo -e "    tdns-mgr.sh admin-token-create john api-token-1"
    echo -e ""
}

show_help_dhcp() {
    echo -e ""
    echo -e "${BLUE}DHCP SERVER MANAGEMENT COMMANDS:${NC}"
    echo -e "    dhcp-scope-list                 List DHCP scopes"
    echo -e "    dhcp-scope-get <name>           Get scope details"
    echo -e "    dhcp-scope-set <name> <start> <end> <mask> [options]"
    echo -e "                                    Set scope configuration"
    echo -e "    dhcp-scope-enable <name>        Enable scope"
    echo -e "    dhcp-scope-disable <name>       Disable scope"
    echo -e "    dhcp-scope-delete <name>        Delete scope"
    echo -e "    dhcp-lease-list                 List DHCP leases"
    echo -e "    dhcp-lease-remove <scope> <mac> Remove a lease"
    echo -e "    dhcp-lease-convert <scope> <mac> <Reserved|Dynamic>"
    echo -e "                                    Convert lease type"
    echo -e ""
    echo -e "${YELLOW}EXAMPLES:${NC}"
    echo -e "    ${GREEN}# List all DHCP scopes${NC}"
    echo -e "    tdns-mgr.sh dhcp-scope-list"
    echo -e ""
    echo -e "    ${GREEN}# Get scope details${NC}"
    echo -e "    tdns-mgr.sh dhcp-scope-get \"Office Network\""
    echo -e ""
    echo -e "    ${GREEN}# Enable a scope${NC}"
    echo -e "    tdns-mgr.sh dhcp-scope-enable \"Office Network\""
    echo -e ""
    echo -e "    ${GREEN}# List all leases${NC}"
    echo -e "    tdns-mgr.sh dhcp-lease-list"
    echo -e ""
    echo -e "    ${GREEN}# Convert a lease to reserved${NC}"
    echo -e "    tdns-mgr.sh dhcp-lease-convert \"Office Network\" \"00:11:22:33:44:55\" Reserved"
    echo -e ""
}

show_help_apps() {
    echo -e ""
    echo -e "${BLUE}APPS MANAGEMENT COMMANDS:${NC}"
    echo -e "    app-list [installed|store]      List apps (installed or store)"
    echo -e "    app-install <name> <url|file>   Install an app"
    echo -e "    app-uninstall <name>            Uninstall an app"
    echo -e "    app-config-get <name>           Get app configuration"
    echo -e "    app-config-set <name> <config>  Set app configuration"
    echo -e ""
    echo -e "${YELLOW}EXAMPLES:${NC}"
    echo -e "    ${GREEN}# List installed apps${NC}"
    echo -e "    tdns-mgr.sh app-list installed"
    echo -e ""
    echo -e "    ${GREEN}# List apps in store${NC}"
    echo -e "    tdns-mgr.sh app-list store"
    echo -e ""
    echo -e "    ${GREEN}# Install an app from URL${NC}"
    echo -e "    tdns-mgr.sh app-install \"Wild IP\" \"https://download.technitium.com/dns/apps/WildIpApp.zip\""
    echo -e ""
    echo -e "    ${GREEN}# Get app configuration${NC}"
    echo -e "    tdns-mgr.sh app-config-get \"Advanced Blocking\""
    echo -e ""
}

show_help_blocked() {
    echo -e ""
    echo -e "${BLUE}BLOCKED & ALLOWED ZONES COMMANDS:${NC}"
    echo -e "    blocked-list [domain]           List blocked zones"
    echo -e "    blocked-add <domain>            Block a domain"
    echo -e "    blocked-delete <domain>         Unblock a domain"
    echo -e "    blocked-flush                   Flush all blocked zones"
    echo -e "    allowed-list [domain]           List allowed zones"
    echo -e "    allowed-add <domain>            Allow a domain"
    echo -e "    allowed-delete <domain>         Remove allowed domain"
    echo -e "    allowed-flush                   Flush all allowed zones"
    echo -e "    blocklists-update               Force update block lists"
    echo -e ""
    echo -e "${YELLOW}EXAMPLES:${NC}"
    echo -e "    ${GREEN}# Block a domain${NC}"
    echo -e "    tdns-mgr.sh blocked-add ads.example.com"
    echo -e ""
    echo -e "    ${GREEN}# List blocked domains${NC}"
    echo -e "    tdns-mgr.sh blocked-list"
    echo -e ""
    echo -e "    ${GREEN}# Allow a domain (whitelist)${NC}"
    echo -e "    tdns-mgr.sh allowed-add safe.example.com"
    echo -e ""
    echo -e "    ${GREEN}# Force update all blocklists${NC}"
    echo -e "    tdns-mgr.sh blocklists-update"
    echo -e ""
}

show_help_logging() {
    echo -e ""
    echo -e "${BLUE}LOGGING & STATS COMMANDS:${NC}"
    echo -e "    log-list                        List log files"
    echo -e "    log-download <file> [limit] [out]"
    echo -e "                                    Download log file"
    echo -e "    log-query <app> <class> [opts]  Query app logs"
    echo -e "    stats-top [type] [duration] [limit]"
    echo -e "                                    Get top stats (TopClients, TopDomains, etc.)"
    echo -e "    server-stats                    Get server statistics"
    echo -e ""
    echo -e "${YELLOW}EXAMPLES:${NC}"
    echo -e "    ${GREEN}# List available log files${NC}"
    echo -e "    tdns-mgr.sh log-list"
    echo -e ""
    echo -e "    ${GREEN}# Download a log file (max 10MB)${NC}"
    echo -e "    tdns-mgr.sh log-download \"2024-01-15.log\" 10 output.log"
    echo -e ""
    echo -e "    ${GREEN}# Query logs${NC}"
    echo -e "    tdns-mgr.sh log-query DnsServerCore.Dns QueryLog"
    echo -e ""
    echo -e "    ${GREEN}# Get top clients for last day (limit 20)${NC}"
    echo -e "    tdns-mgr.sh stats-top TopClients LastDay 20"
    echo -e ""
    echo -e "    ${GREEN}# Get server statistics${NC}"
    echo -e "    tdns-mgr.sh server-stats"
    echo -e ""
}

show_help_dnssec() {
    echo -e ""
    echo -e "${BLUE}DNSSEC MANAGEMENT COMMANDS:${NC}"
    echo -e "    dnssec-sign <zone> [algo] [curve]"
    echo -e "                                    Sign zone with DNSSEC"
    echo -e "    dnssec-unsign <zone>            Unsign zone"
    echo -e "    dnssec-status <zone>            Get DNSSEC status & DS records"
    echo -e ""
    echo -e "${YELLOW}EXAMPLES:${NC}"
    echo -e "    ${GREEN}# Sign a zone with default algorithm${NC}"
    echo -e "    tdns-mgr.sh dnssec-sign example.com"
    echo -e ""
    echo -e "    ${GREEN}# Sign with specific algorithm${NC}"
    echo -e "    tdns-mgr.sh dnssec-sign example.com ECDSAP256SHA256"
    echo -e ""
    echo -e "    ${GREEN}# Get DNSSEC status and DS records${NC}"
    echo -e "    tdns-mgr.sh dnssec-status example.com"
    echo -e ""
    echo -e "    ${GREEN}# Unsign a zone${NC}"
    echo -e "    tdns-mgr.sh dnssec-unsign example.com"
    echo -e ""
}

show_help_settings() {
    echo -e ""
    echo -e "${BLUE}ADVANCED ZONE & SERVER SETTINGS COMMANDS:${NC}"
    echo -e "    settings-get                    Get server settings"
    echo -e "    settings-set <opt=val> ...      Set server settings"
    echo -e "    zone-options-get <zone>         Get zone options"
    echo -e "    zone-options-set <zone> <opt=val> ..."
    echo -e "                                    Set zone options"
    echo -e "    catalog-list                    List catalog zones"
    echo -e ""
    echo -e "${YELLOW}EXAMPLES:${NC}"
    echo -e "    ${GREEN}# Get server settings${NC}"
    echo -e "    tdns-mgr.sh settings-get"
    echo -e ""
    echo -e "    ${GREEN}# Set server settings${NC}"
    echo -e "    tdns-mgr.sh settings-set dnsServerDomain=dns.example.com"
    echo -e ""
    echo -e "    ${GREEN}# Get zone options${NC}"
    echo -e "    tdns-mgr.sh zone-options-get example.com"
    echo -e ""
    echo -e "    ${GREEN}# Set zone options${NC}"
    echo -e "    tdns-mgr.sh zone-options-set example.com disabled=false"
    echo -e ""
    echo -e "    ${GREEN}# List catalog zones${NC}"
    echo -e "    tdns-mgr.sh catalog-list"
    echo -e ""
}

show_help_client() {
    echo -e ""
    echo -e "${BLUE}DNS CLIENT COMMANDS:${NC}"
    echo -e "    client-resolve <domain> [type] [server] [protocol] [options]"
    echo -e "                                    Resolve using DNS client"
    echo -e "                                    Server: recursive-resolver, system-dns, or IP"
    echo -e "                                    Protocol: UDP, TCP, TLS, HTTPS, QUIC"
    echo -e "    query <domain> [type]           Simple query (legacy)"
    echo -e ""
    echo -e "${YELLOW}EXAMPLES:${NC}"
    echo -e "    ${GREEN}# Simple query${NC}"
    echo -e "    tdns-mgr.sh query example.com A"
    echo -e ""
    echo -e "    ${GREEN}# Resolve using recursive resolver${NC}"
    echo -e "    tdns-mgr.sh client-resolve example.com A recursive-resolver UDP"
    echo -e ""
    echo -e "    ${GREEN}# Resolve using specific DNS server over TLS${NC}"
    echo -e "    tdns-mgr.sh client-resolve example.com A 8.8.8.8 TLS"
    echo -e ""
    echo -e "    ${GREEN}# Resolve with DNSSEC validation${NC}"
    echo -e "    tdns-mgr.sh client-resolve example.com A recursive-resolver HTTPS import=true"
    echo -e ""
}

show_help_verbose() {
    print_header
    
    echo -e "USAGE:"
    echo -e "    tdns-mgr.sh [options] [command] [args]"
    echo -e ""
    echo -e "OPTIONS:"
    echo -e "    -q, --quiet, --silent           Suppress informational output (useful for scripting)"
    echo -e "    -h, --help [topic]              Show help (optionally for a specific topic)"
    echo -e "    -v, --version                   Show version"
    echo -e "    --verbose                       Show verbose help with all commands"
    echo -e "    --debug                         Show debug information (API calls, responses, etc.)"
    
    # Call all topic-specific help functions
    show_help_authentication
    show_help_dns
    show_help_cluster
    show_help_administration
    show_help_dhcp
    show_help_apps
    show_help_blocked
    show_help_logging
    show_help_dnssec
    show_help_settings
    show_help_client
    
    # Show environment variables and documentation
    echo -e "${CYAN}ENVIRONMENT VARIABLES:${NC}"
    echo -e "    DNS_SERVER      DNS server hostname/IP (default: localhost)"
    echo -e "    DNS_PORT        DNS server port (default: 5380)"
    echo -e "    DNS_PROTOCOL    Protocol to use: http or https (default: https)"
    echo -e "    DNS_USER        Username (default: admin)"
    echo -e "    DNS_PASS        Password (for non-interactive login)"
    echo -e "    DNS_TOKEN       API token (set after login)"
    echo -e ""
    echo -e "${CYAN}CONFIGURATION FILE:${NC}"
    echo -e "    Checked in order: CLI args, ~/.config/tdns-mgr/.tdns-mgr.conf,"
    echo -e "                      /etc/tdns-mgr/.tdns-mgr.conf, script/.tdns-mgr.conf"
    echo -e "    Saved to: ~/.config/tdns-mgr/.tdns-mgr.conf"
    echo -e ""
    echo -e "${CYAN}DOCUMENTATION:${NC}"
    echo -e "    See EXAMPLES.md for detailed usage examples"
    echo -e "    API Documentation: https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md"
    echo -e ""
}

################################################################################
# Main Function
################################################################################

main() {
    # Parse global options
    local verbose_help=false
    while [[ "${1:-}" == "-q" || "${1:-}" == "--quiet" || "${1:-}" == "--silent" || "${1:-}" == "--verbose" || "${1:-}" == "--debug" ]]; do
        if [[ "$1" == "--verbose" ]]; then
            verbose_help=true
            shift
        elif [[ "$1" == "--debug" ]]; then
            DEBUG=true
            shift
        elif [[ "$1" == "-q" || "$1" == "--quiet" || "$1" == "--silent" ]]; then
            QUIET=true
            shift
        fi
    done

    load_config

    if [[ $# -eq 0 ]]; then
        check_dependencies
        show_summary
        exit 0
    fi
    
    # Check dependencies for execution
    if [[ "$1" != "help" && "$1" != "--help" && "$1" != "-h" && "$1" != "--version" && "$1" != "-v" ]]; then
        check_dependencies
    fi
    
    local command="$1"
    shift
    
    case "$command" in
        # Help system
        help|--help|-h)
            local topic="${1:-}"
            # Check if --verbose is passed as a topic
            if [[ "$topic" == "--verbose" ]]; then
                verbose_help=true
                topic=""
            fi
            
            if [[ "$verbose_help" == "true" ]]; then
                show_help_verbose
            elif [[ -n "$topic" ]]; then
                # Convert to lowercase for case-insensitive matching (bash 3.2+ compatible)
                local topic_lower
                topic_lower=$(echo "$topic" | tr '[:upper:]' '[:lower:]')
                case "$topic_lower" in
                    authentication|auth|login)
                        show_help_authentication
                        ;;
                    dns|zones|records)
                        show_help_dns
                        ;;
                    cluster|clustering)
                        show_help_cluster
                        ;;
                    administration|admin|users|groups)
                        show_help_administration
                        ;;
                    dhcp)
                        show_help_dhcp
                        ;;
                    apps|applications)
                        show_help_apps
                        ;;
                    blocked|allowed|blocklist|whitelist)
                        show_help_blocked
                        ;;
                    logging|logs|stats|statistics)
                        show_help_logging
                        ;;
                    dnssec)
                        show_help_dnssec
                        ;;
                    settings|config|configuration)
                        show_help_settings
                        ;;
                    client|resolve)
                        show_help_client
                        ;;
                    *)
                        print_error "Unknown help topic: $topic"
                        echo ""
                        show_summary
                        exit 1
                        ;;
                esac
            else
                show_summary
            fi
            exit 0
            ;;
        
        # Version
        version|--version|-v)
            echo "DNS Manager v${VERSION}"
            exit 0
            ;;
        
        # Authentication
        login)
            cmd_login "$@"
            ;;
        logout)
            cmd_logout "$@"
            ;;
        change-password)
            cmd_change_password "$@"
            ;;
        check-update)
            cmd_check_update "$@"
            ;;
        config)
            cmd_config "$@"
            ;;
        
        # Zone Management
        list-zones)
            cmd_list_zones "$@"
            ;;
        create-zone)
            cmd_create_zone "$@"
            ;;
        delete-zone)
            cmd_delete_zone "$@"
            ;;
        enable-zone)
            cmd_enable_zone "$@"
            ;;
        disable-zone)
            cmd_disable_zone "$@"
            ;;
        export-zone)
            cmd_export_zone "$@"
            ;;
        import-zone)
            cmd_import_zone "$@"
            ;;
        export-zones)
            cmd_export_zones "$@"
            ;;
        import-zones)
            cmd_import_zones "$@"
            ;;
        
        # Record Management
        list-records)
            cmd_list_records "$@"
            ;;
        add-record)
            cmd_add_record "$@"
            ;;
        update-record)
            cmd_update_record "$@"
            ;;
        delete-record)
            cmd_delete_record "$@"
            ;;
        import-records)
            cmd_import_records "$@"
            ;;
        
        # Server Management
        server-status)
            cmd_server_status "$@"
            ;;
        server-stats)
            cmd_server_stats "$@"
            ;;
        flush-cache)
            cmd_flush_cache "$@"
            ;;
        query)
            cmd_query "$@"
            ;;
        
        # Cluster Management
        cluster-status)
            cmd_cluster_status "$@"
            ;;
        cluster-init)
            cmd_cluster_init "$@"
            ;;
        cluster-join)
            cmd_cluster_join "$@"
            ;;
        cluster-leave)
            cmd_cluster_leave "$@"
            ;;
        cluster-promote)
            cmd_cluster_promote "$@"
            ;;
        cluster-resync)
            cmd_cluster_resync "$@"
            ;;
        
        # Administration
        admin-user-list)
            cmd_admin_user_list "$@"
            ;;
        admin-user-create)
            cmd_admin_user_create "$@"
            ;;
        admin-user-delete)
            cmd_admin_user_delete "$@"
            ;;
        admin-group-list)
            cmd_admin_group_list "$@"
            ;;
        admin-group-create)
            cmd_admin_group_create "$@"
            ;;
        admin-group-delete)
            cmd_admin_group_delete "$@"
            ;;
        admin-perm-list)
            cmd_admin_perm_list "$@"
            ;;
        admin-session-list)
            cmd_admin_session_list "$@"
            ;;
        admin-session-delete)
            cmd_admin_session_delete "$@"
            ;;
        admin-token-create)
            cmd_admin_token_create "$@"
            ;;
        
        # DHCP Management
        dhcp-scope-list)
            cmd_dhcp_scope_list "$@"
            ;;
        dhcp-scope-get)
            cmd_dhcp_scope_get "$@"
            ;;
        dhcp-scope-set)
            cmd_dhcp_scope_set "$@"
            ;;
        dhcp-scope-enable)
            cmd_dhcp_scope_enable "$@"
            ;;
        dhcp-scope-disable)
            cmd_dhcp_scope_disable "$@"
            ;;
        dhcp-scope-delete)
            cmd_dhcp_scope_delete "$@"
            ;;
        dhcp-lease-list)
            cmd_dhcp_lease_list "$@"
            ;;
        dhcp-lease-remove)
            cmd_dhcp_lease_remove "$@"
            ;;
        dhcp-lease-convert)
            cmd_dhcp_lease_convert "$@"
            ;;
        
        # Apps Management
        app-list)
            cmd_app_list "$@"
            ;;
        app-install)
            cmd_app_install "$@"
            ;;
        app-uninstall)
            cmd_app_uninstall "$@"
            ;;
        app-config-get)
            cmd_app_config_get "$@"
            ;;
        app-config-set)
            cmd_app_config_set "$@"
            ;;
        
        # Blocked & Allowed Zones
        blocked-list)
            cmd_blocked_list "$@"
            ;;
        blocked-add)
            cmd_blocked_add "$@"
            ;;
        blocked-delete)
            cmd_blocked_delete "$@"
            ;;
        blocked-flush)
            cmd_blocked_flush "$@"
            ;;
        allowed-list)
            cmd_allowed_list "$@"
            ;;
        allowed-add)
            cmd_allowed_add "$@"
            ;;
        allowed-delete)
            cmd_allowed_delete "$@"
            ;;
        allowed-flush)
            cmd_allowed_flush "$@"
            ;;
        blocklists-update)
            cmd_blocklists_update "$@"
            ;;
        
        # Logging & Stats
        log-list)
            cmd_log_list "$@"
            ;;
        log-download)
            cmd_log_download "$@"
            ;;
        log-query)
            cmd_log_query "$@"
            ;;
        stats-top)
            cmd_stats_top "$@"
            ;;
        
        # DNSSEC Management
        dnssec-sign)
            cmd_dnssec_sign "$@"
            ;;
        dnssec-unsign)
            cmd_dnssec_unsign "$@"
            ;;
        dnssec-status)
            cmd_dnssec_status "$@"
            ;;
        
        # Settings & Advanced
        settings-get)
            cmd_settings_get "$@"
            ;;
        settings-set)
            cmd_settings_set "$@"
            ;;
        zone-options-get)
            cmd_zone_options_get "$@"
            ;;
        zone-options-set)
            cmd_zone_options_set "$@"
            ;;
        catalog-list)
            cmd_catalog_list "$@"
            ;;
        
        # DNS Client
        client-resolve)
            cmd_client_resolve "$@"
            ;;
        
        *)
            print_error "Unknown command: $command"
            echo ""
            show_summary
            exit 1
            ;;
    esac
}

# Run main function
main "$@"

