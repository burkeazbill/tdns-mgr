#!/usr/bin/bash

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
VERSION="1.0.0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[38;2;0;176;255m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration file
# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Configuration file
if [[ -f "${SCRIPT_DIR}/.tdns-mgr.conf" ]]; then
    CONFIG_FILE="${SCRIPT_DIR}/.tdns-mgr.conf"
else
    CONFIG_FILE="${HOME}/.tdns-mgr.conf"
fi

# Default values
DNS_SERVER="${DNS_SERVER:-localhost}"
DNS_PORT="${DNS_PORT:-5380}"
DNS_TOKEN="${DNS_TOKEN:-}"
DNS_USER="${DNS_USER:-admin}"
DNS_PASS="${DNS_PASS:-}"
QUIET="${QUIET:-false}"

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

# Load configuration
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    fi
}

# Save configuration
save_config() {
    cat > "$CONFIG_FILE" << EOF
DNS_SERVER="$DNS_SERVER"
DNS_PORT="$DNS_PORT"
DNS_TOKEN="$DNS_TOKEN"
DNS_USER="$DNS_USER"
EOF
    chmod 600 "$CONFIG_FILE"
    print_success "Configuration saved to $CONFIG_FILE"
}

# API call wrapper
api_call() {
    local endpoint="$1"
    shift
    local url="http://${DNS_SERVER}:${DNS_PORT}/api/${endpoint}"
    
    if [[ -n "$DNS_TOKEN" ]]; then
        curl -s -X POST "$url" \
            -H "Authorization: Bearer $DNS_TOKEN" \
            "$@"
    else
        curl -s -X POST "$url" "$@"
    fi
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
    
    local url="http://${DNS_SERVER}:${DNS_PORT}/api/zones/export?token=${DNS_TOKEN}&zone=${zone}&format=Bind"
    
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
    
    local url="http://${DNS_SERVER}:${DNS_PORT}/api/zones/import?token=${DNS_TOKEN}&zone=${zone}&overwrite=true"
    
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
    
    local url="http://${DNS_SERVER}:${DNS_PORT}/api/settings/backup?token=${DNS_TOKEN}&zones=true"
    
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
    
    local url="http://${DNS_SERVER}:${DNS_PORT}/api/settings/restore?token=${DNS_TOKEN}&zones=true&deleteExistingFiles=true"
    
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
            # Fallback for non-gawk (standard awk doesn''t support FPAT)
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
        local url="http://${DNS_SERVER}:${DNS_PORT}/api/zones/records/add"
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
    
    if curl -s -f "http://${DNS_SERVER}:${DNS_PORT}" > /dev/null 2>&1; then
        print_success "DNS Server is running at ${DNS_SERVER}:${DNS_PORT}"
    else
        print_error "DNS Server is not accessible at ${DNS_SERVER}:${DNS_PORT}"
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
# Configuration Functions
################################################################################

cmd_config() {
    local action="${1:-show}"
    
    case "$action" in
        show)
            print_info "Current configuration:"
            echo "  Server: ${DNS_SERVER}"
            echo "  Port: ${DNS_PORT}"
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
                user)
                    DNS_USER="$value"
                    save_config
                    print_success "User set to: $value"
                    ;;
                *)
                    print_error "Unknown config key: $key"
                    print_info "Valid keys: server, port, user"
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

show_menu() {
    print_header
    
    cat << 'EOF'
USAGE:
    tdns-mgr.sh [options] [command] [args]

OPTIONS:
    -q, --quiet, --silent           Suppress informational output (useful for scripting)
    -h, --help                      Show this help message
    -v, --version                   Show version

AUTHENTICATION COMMANDS:
    login                           Login to DNS server
    logout                          Logout from DNS server
    change-password <new_pass>      Change user password
    config [show|set]               Show or set configuration

ZONE MANAGEMENT:
    list-zones                      List all DNS zones
    create-zone <domain> [type]     Create a new zone
                                    Types: Primary, Secondary, Stub, Forwarder
    delete-zone <domain>            Delete a zone
    enable-zone <domain>            Enable a zone
    disable-zone <domain>           Disable a zone
    export-zone <domain> [file]     Export a single zone (BIND format)
    import-zone <domain> <file>     Import a single zone (BIND format)
    export-zones [file]             Export all zones (to zip)
    import-zones <file>             Import all zones (from zip)

RECORD MANAGEMENT:
    list-records <zone>             List all records in a zone
    add-record <zone> <name> <type> <value> [ttl] [--ptr]
                                    Add a DNS record (use --ptr with A/AAAA for auto reverse lookup)
    update-record <zone> <name> <type> <old> <new> [ttl]
                                    Update a DNS record
    delete-record <zone> <name> <type> [value]
                                    Delete a DNS record
    import-records <file> [--ptr]   Import records from CSV file
                                    Columns: zone,name,type,value

SERVER MANAGEMENT:
    server-status                   Check if server is running
    server-stats                    Get server statistics
    flush-cache                     Flush DNS cache
    query <domain> [type]           Query DNS records

EXAMPLES:
    # Login
    tdns-mgr.sh login

    # Create a zone
    tdns-mgr.sh create-zone example.com Primary

    # Add an A record
    tdns-mgr.sh add-record example.com www A 192.168.1.100

    # Add a CNAME record
    tdns-mgr.sh add-record example.com mail CNAME mail.example.com

    # Add an MX record
    tdns-mgr.sh add-record example.com @ MX mail.example.com 10

    # List all records
    tdns-mgr.sh list-records example.com

    # Query a domain
    tdns-mgr.sh query www.example.com A

    # Delete a record
    tdns-mgr.sh delete-record example.com www A 192.168.1.100

    # Get server stats
    tdns-mgr.sh server-stats

ENVIRONMENT VARIABLES:
    DNS_SERVER      DNS server hostname/IP (default: localhost)
    DNS_PORT        DNS server port (default: 5380)
    DNS_USER        Username (default: admin)
    DNS_PASS        Password (for non-interactive login)
    DNS_TOKEN       API token (set after login)

CONFIGURATION FILE:
    ~/.tdns-mgr.conf

For more information, see: tdns-mgr.md
API Documentation: https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md

EOF
}

################################################################################
# Main Function
################################################################################

main() {
    load_config
    
    # Parse global options
    while [[ "${1:-}" == "-q" || "${1:-}" == "--quiet" || "${1:-}" == "--silent" ]]; do
        QUIET=true
        shift
    done

    if [[ $# -eq 0 ]]; then
        check_dependencies
        show_menu
        exit 0
    fi
    
    # Check dependencies for execution
    if [[ "$1" != "help" && "$1" != "--help" && "$1" != "-h" && "$1" != "--version" && "$1" != "-v" ]]; then
        check_dependencies
    fi
    
    local command="$1"
    shift
    
    case "$command" in
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
        
        # Help
        help|--help|-h)
            show_menu
            ;;
        
        # Version
        version|--version|-v)
            echo "DNS Manager v${VERSION}"
            ;;
        
        *)
            print_error "Unknown command: $command"
            echo ""
            show_menu
            exit 1
            ;;
    esac
}

# Run main function
main "$@"

