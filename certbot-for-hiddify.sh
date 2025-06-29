#!/bin/bash

# Enhanced SSL Certificate Manager for Hiddify
# Author: Ryuk-74

set -uo pipefail

# Configuration
readonly SCRIPT_NAME="SSL Certificate Manager"
readonly SCRIPT_VERSION="1.1"
readonly DOMAINS_FILE="domains.txt"
readonly OUTPUT_DIR="/opt/hiddify-manager/ssl"
readonly LETSENCRYPT_DIR="/etc/letsencrypt/live"
readonly LOG_FILE="/var/log/ssl-cert-manager.log"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Global variables
declare -a DOMAINS=()

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    case "$level" in
        "ERROR")   echo -e "${RED}[!] $message${NC}" ;;
        "SUCCESS") echo -e "${GREEN}[✓] $message${NC}" ;;
        "INFO")    echo -e "${BLUE}[*] $message${NC}" ;;
        "WARN")    echo -e "${YELLOW}[⚠] $message${NC}" ;;
        *)         echo "[$level] $message" ;;
    esac
}

# Utility functions
show_header() {
    clear
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  $SCRIPT_NAME v$SCRIPT_VERSION${NC}"
    echo -e "${BLUE}  Enhanced by Ryuk-74${NC}"
    echo -e "${BLUE}================================${NC}"
    echo
}

confirm_action() {
    local prompt="$1"
    local response
    read -p "$prompt (y/N): " response
    [[ "${response,,}" =~ ^(yes|y)$ ]]
}

validate_domain() {
    local domain="$1"
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        log "ERROR" "Invalid domain format: $domain"
        return 1
    fi
    return 0
}

check_prerequisites() {
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "This script must be run as root (use sudo)"
        exit 1
    fi
    
    # Create necessary directories
    mkdir -p "$OUTPUT_DIR" || {
        log "ERROR" "Failed to create output directory: $OUTPUT_DIR"
        exit 1
    }
    
    # Create log file
    touch "$LOG_FILE" || {
        log "WARN" "Could not create log file: $LOG_FILE"
    }
    
    log "INFO" "Prerequisites checked successfully"
}

# Domain management functions
load_domains() {
    if [[ -f "$DOMAINS_FILE" ]]; then
        mapfile -t DOMAINS < "$DOMAINS_FILE"
        # Remove empty lines
        local temp_domains=()
        for domain in "${DOMAINS[@]}"; do
            if [[ -n "$domain" ]]; then
                temp_domains+=("$domain")
            fi
        done
        DOMAINS=("${temp_domains[@]}")
        log "INFO" "Loaded ${#DOMAINS[@]} domains from $DOMAINS_FILE"
    else
        DOMAINS=()
        log "INFO" "No domains file found, starting with empty list"
    fi
}

save_domains() {
    if [[ ${#DOMAINS[@]} -gt 0 ]]; then
        printf "%s\n" "${DOMAINS[@]}" > "$DOMAINS_FILE"
        log "SUCCESS" "Domains saved to $DOMAINS_FILE"
    else
        > "$DOMAINS_FILE"  # Create empty file
        log "INFO" "Empty domains list saved"
    fi
}

list_domains() {
    if [[ ${#DOMAINS[@]} -eq 0 ]]; then
        log "INFO" "No domains configured"
        return 1
    fi
    
    echo "Current domains:"
    for i in "${!DOMAINS[@]}"; do
        local cert_status=""
        if [[ -f "$OUTPUT_DIR/${DOMAINS[$i]}.crt" ]]; then
            # Check certificate expiry
            local expiry=$(openssl x509 -in "$OUTPUT_DIR/${DOMAINS[$i]}.crt" -noout -enddate 2>/dev/null | cut -d= -f2 2>/dev/null || echo "Unknown")
            cert_status=" ${GREEN}[✓ Certificate exists - Expires: $expiry]${NC}"
        else
            cert_status=" ${RED}[✗ No certificate]${NC}"
        fi
        echo -e "$((i+1)). ${DOMAINS[$i]}$cert_status"
    done
    return 0
}

add_domain() {
    local new_domain
    echo
    read -p "Enter new domain: " new_domain
    
    if [[ -z "$new_domain" ]]; then
        log "ERROR" "Domain cannot be empty"
        return 1
    fi
    
    if ! validate_domain "$new_domain"; then
        return 1
    fi
    
    # Check for duplicates
    for domain in "${DOMAINS[@]}"; do
        if [[ "$domain" == "$new_domain" ]]; then
            log "ERROR" "Domain already exists: $new_domain"
            return 1
        fi
    done
    
    DOMAINS+=("$new_domain")
    save_domains
    log "SUCCESS" "Domain added: $new_domain"
}

edit_domain() {
    if ! list_domains; then
        return 1
    fi
    
    local idx new_domain old_domain
    echo
    read -p "Select domain number to edit: " idx
    
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ $idx -lt 1 ]] || [[ $idx -gt ${#DOMAINS[@]} ]]; then
        log "ERROR" "Invalid selection"
        return 1
    fi
    
    idx=$((idx-1))
    old_domain="${DOMAINS[$idx]}"
    
    echo "Current value: $old_domain"
    read -p "Enter new value: " new_domain
    
    if [[ -z "$new_domain" ]]; then
        log "ERROR" "Domain cannot be empty"
        return 1
    fi
    
    if ! validate_domain "$new_domain"; then
        return 1
    fi
    
    if [[ "$old_domain" == "$new_domain" ]]; then
        log "INFO" "No changes made"
        return 0
    fi
    
    # Check for duplicates
    for i in "${!DOMAINS[@]}"; do
        if [[ $i -ne $idx && "${DOMAINS[$i]}" == "$new_domain" ]]; then
            log "ERROR" "Domain already exists: $new_domain"
            return 1
        fi
    done
    
    DOMAINS[$idx]="$new_domain"
    delete_cert_files "$old_domain"
    save_domains
    
    log "SUCCESS" "Domain updated: $old_domain → $new_domain"
    
    if confirm_action "Request certificate for the new domain?"; then
        request_cert "$new_domain"
    fi
}

delete_domain() {
    if ! list_domains; then
        return 1
    fi
    
    local idx domain
    echo
    read -p "Select domain number to delete: " idx
    
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ $idx -lt 1 ]] || [[ $idx -gt ${#DOMAINS[@]} ]]; then
        log "ERROR" "Invalid selection"
        return 1
    fi
    
    idx=$((idx-1))
    domain="${DOMAINS[$idx]}"
    
    if ! confirm_action "Delete domain '$domain' and its certificates?"; then
        log "INFO" "Deletion cancelled"
        return 0
    fi
    
    # Revoke certificate if it exists
    if [[ -f "$OUTPUT_DIR/$domain.crt" ]]; then
        if confirm_action "Also revoke the certificate from Let's Encrypt?"; then
            revoke_cert "$domain"
        fi
    fi
    
    unset 'DOMAINS[$idx]'
    DOMAINS=("${DOMAINS[@]}")  # Reindex array
    delete_cert_files "$domain"
    save_domains
    
    log "SUCCESS" "Domain deleted: $domain"
}

# Certificate management functions
delete_cert_files() {
    local domain="$1"
    local cert_file="$OUTPUT_DIR/$domain.crt"
    local key_file="$OUTPUT_DIR/$domain.crt.key"
    
    if [[ -f "$cert_file" ]] || [[ -f "$key_file" ]]; then
        rm -f "$cert_file" "$key_file"
        log "INFO" "Certificate files removed for: $domain"
    fi
}

check_existing_cert() {
    local domain="$1"
    local cert_file="$OUTPUT_DIR/$domain.crt"
    
    if [[ -f "$cert_file" ]]; then
        local expiry=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2 2>/dev/null || echo "Unknown")
        log "WARN" "Certificate already exists for $domain (expires: $expiry)"
        
        if confirm_action "Do you want to revoke the existing certificate before issuing a new one?"; then
            if revoke_cert "$domain"; then
                log "INFO" "Existing certificate revoked, proceeding with new certificate"
                return 0
            else
                log "ERROR" "Failed to revoke existing certificate"
                if ! confirm_action "Continue with new certificate anyway?"; then
                    return 1
                fi
            fi
        else
            if ! confirm_action "Continue and overwrite the existing certificate?"; then
                log "INFO" "Certificate request cancelled"
                return 1
            fi
        fi
    fi
    return 0
}

revoke_cert() {
    local domain="$1"
    local cert_file="$OUTPUT_DIR/$domain.crt"
    local letsencrypt_cert="$LETSENCRYPT_DIR/$domain/fullchain.pem"
    
    if [[ ! -f "$cert_file" && ! -f "$letsencrypt_cert" ]]; then
        log "ERROR" "No certificate found for $domain"
        return 1
    fi
    
    log "INFO" "Revoking certificate for: $domain"
    
    # Try to revoke using the Let's Encrypt certificate first
    local cert_to_revoke="$letsencrypt_cert"
    if [[ ! -f "$cert_to_revoke" ]]; then
        cert_to_revoke="$cert_file"
    fi
    
    if certbot revoke --cert-path "$cert_to_revoke" --non-interactive 2>&1 | tee -a "$LOG_FILE"; then
        log "SUCCESS" "Certificate revoked for $domain"
        
        # Clean up Let's Encrypt files
        if [[ -d "$LETSENCRYPT_DIR/$domain" ]]; then
            rm -rf "$LETSENCRYPT_DIR/$domain"
            log "INFO" "Let's Encrypt certificate files removed for $domain"
        fi
        
        # Remove our certificate files
        delete_cert_files "$domain"
        return 0
    else
        log "ERROR" "Failed to revoke certificate for $domain"
        return 1
    fi
}

revoke_single_cert() {
    if ! list_domains; then
        return 1
    fi
    
    local idx
    echo
    read -p "Select domain number to revoke certificate: " idx
    
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ $idx -lt 1 ]] || [[ $idx -gt ${#DOMAINS[@]} ]]; then
        log "ERROR" "Invalid selection"
        return 1
    fi
    
    idx=$((idx-1))
    local domain="${DOMAINS[$idx]}"
    
    if [[ ! -f "$OUTPUT_DIR/$domain.crt" ]]; then
        log "ERROR" "No certificate found for $domain"
        return 1
    fi
    
    if confirm_action "Are you sure you want to revoke the certificate for '$domain'?"; then
        revoke_cert "$domain"
    else
        log "INFO" "Certificate revocation cancelled"
    fi
}

check_certbot_installed() {
    if command -v certbot >/dev/null 2>&1; then
        log "SUCCESS" "Certbot is already installed"
        return 0
    else
        log "WARN" "Certbot is not installed"
        return 1
    fi
}

install_certbot() {
    if check_certbot_installed; then
        return 0
    fi
    
    log "INFO" "Installing Certbot..."
    
    if command -v snap >/dev/null 2>&1; then
        if snap install --classic certbot; then
            log "SUCCESS" "Certbot installed via snap"
        else
            log "ERROR" "Failed to install Certbot via snap"
            return 1
        fi
    elif command -v apt-get >/dev/null 2>&1; then
        if apt-get update && apt-get install -y certbot; then
            log "SUCCESS" "Certbot installed via apt"
        else
            log "ERROR" "Failed to install Certbot via apt"
            return 1
        fi
    elif command -v yum >/dev/null 2>&1; then
        if yum install -y certbot; then
            log "SUCCESS" "Certbot installed via yum"
        else
            log "ERROR" "Failed to install Certbot via yum"
            return 1
        fi
    else
        log "ERROR" "No supported package manager found (snap, apt, yum)"
        return 1
    fi
}

request_cert() {
    local domain="$1"
    
    if ! validate_domain "$domain"; then
        return 1
    fi
    
    # Check for existing certificate and ask about revocation
    if ! check_existing_cert "$domain"; then
        return 1
    fi
    
    log "INFO" "Requesting certificate for: $domain"
    
    # Ask user for challenge method (removed webroot option)
    echo "Select challenge method:"
    echo "1. Standalone (requires port 80 to be free)"
    echo "2. Manual DNS challenge (no ports required)"
    read -p "Choose method [1-2]: " method
    
    local cert_src="$LETSENCRYPT_DIR/$domain/fullchain.pem"
    local key_src="$LETSENCRYPT_DIR/$domain/privkey.pem"
    local cert_dest="$OUTPUT_DIR/$domain.crt"
    local key_dest="$OUTPUT_DIR/$domain.crt.key"
    
    local certbot_success=false
    
    case "$method" in
        1)
            # Check if port 80 is available
            if netstat -tlnp 2>/dev/null | grep -q ":80 "; then
                log "WARN" "Port 80 appears to be in use. This may fail."
                if ! confirm_action "Continue anyway?"; then
                    return 1
                fi
            fi
            log "INFO" "Running standalone challenge..."
            if certbot certonly --standalone --non-interactive --agree-tos --register-unsafely-without-email --force-renewal -d "$domain" 2>&1 | tee -a "$LOG_FILE"; then
                certbot_success=true
            fi
            ;;
        2)
            log "INFO" "Using manual DNS challenge method"
            log "WARN" "You will need to manually add DNS TXT records as prompted"
            echo "Press Enter to continue with DNS challenge..."
            read
            
            # Manual DNS challenge requires interaction, so we remove --non-interactive
            # Check certbot version for compatibility
            if certbot --help | grep -q "manual-public-ip-logging-ok"; then
                if certbot certonly --manual --preferred-challenges dns --agree-tos --register-unsafely-without-email --force-renewal --manual-public-ip-logging-ok -d "$domain" 2>&1 | tee -a "$LOG_FILE"; then
                    certbot_success=true
                fi
            else
                # Older version of certbot without --manual-public-ip-logging-ok flag
                if certbot certonly --manual --preferred-challenges dns --agree-tos --register-unsafely-without-email --force-renewal -d "$domain" 2>&1 | tee -a "$LOG_FILE"; then
                    certbot_success=true
                fi
            fi
            ;;
        *)
            log "ERROR" "Invalid method selection"
            return 1
            ;;
    esac
    
    # Check results
    if [[ "$certbot_success" == true ]]; then
        # Check if certificate files were actually created
        if [[ -f "$cert_src" && -f "$key_src" ]]; then
            if cp "$cert_src" "$cert_dest" && cp "$key_src" "$key_dest"; then
                chmod 644 "$cert_dest" 2>/dev/null || true
                chmod 600 "$key_dest" 2>/dev/null || true
                log "SUCCESS" "Certificate saved for $domain"
                
                # Show certificate info
                local expiry=$(openssl x509 -in "$cert_dest" -noout -enddate 2>/dev/null | cut -d= -f2 2>/dev/null || echo "Unknown")
                log "INFO" "Certificate expires: $expiry"
                return 0
            else
                log "ERROR" "Failed to copy certificate files for $domain"
                return 1
            fi
        else
            log "ERROR" "Certificate files not found after certbot run for $domain"
            return 1
        fi
    else
        log "ERROR" "Certbot command failed for $domain"
        return 1
    fi
}

request_all_certs() {
    if [[ ${#DOMAINS[@]} -eq 0 ]]; then
        log "ERROR" "No domains configured"
        return 1
    fi
    
    local success_count=0
    local total_count=${#DOMAINS[@]}
    
    log "INFO" "Requesting certificates for $total_count domains..."
    
    for domain in "${DOMAINS[@]}"; do
        echo
        log "INFO" "Processing domain: $domain"
        if request_cert "$domain"; then
            ((success_count++))
        else
            log "ERROR" "Failed to process: $domain"
        fi
        sleep 2  # Brief pause between requests
    done
    
    echo
    log "INFO" "Certificate request completed: $success_count/$total_count successful"
}

request_single_cert() {
    if ! list_domains; then
        return 1
    fi
    
    local idx
    echo
    read -p "Select domain number: " idx
    
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ $idx -lt 1 ]] || [[ $idx -gt ${#DOMAINS[@]} ]]; then
        log "ERROR" "Invalid selection"
        return 1
    fi
    
    idx=$((idx-1))
    request_cert "${DOMAINS[$idx]}"
}

# Menu functions
show_menu() {
    local title="$1"
    shift
    local options=("$@")
    
    echo
    echo "$title"
    echo "$(printf '=%.0s' $(seq 1 ${#title}))"
    for i in "${!options[@]}"; do
        echo "$((i+1)). ${options[$i]}"
    done
    echo
}

domain_menu() {
    while true; do
        show_header
        show_menu "Domain Management" \
            "Add Domain" \
            "Edit Domain" \
            "Delete Domain" \
            "List Domains" \
            "Back to Main Menu"
        
        read -p "Select option [1-5]: " choice
        
        case "$choice" in
            1) add_domain ;;
            2) edit_domain ;;
            3) delete_domain ;;
            4) list_domains ;;
            5) break ;;
            *) log "ERROR" "Invalid option: $choice" ;;
        esac
        
        if [[ "$choice" != "5" ]]; then
            echo
            read -p "Press Enter to continue..."
        fi
    done
}

cert_menu() {
    while true; do
        show_header
        show_menu "Certificate Management" \
            "Request All Certificates" \
            "Request Single Certificate" \
            "Revoke Certificate" \
            "Check Certbot Status" \
            "Back to Main Menu"
        
        read -p "Select option [1-5]: " choice
        
        case "$choice" in
            1) request_all_certs ;;
            2) request_single_cert ;;
            3) revoke_single_cert ;;
            4) check_certbot_installed ;;
            5) break ;;
            *) log "ERROR" "Invalid option: $choice" ;;
        esac
        
        if [[ "$choice" != "5" ]]; then
            echo
            read -p "Press Enter to continue..."
        fi
    done
}

main_menu() {
    load_domains
    
    while true; do
        show_header
        echo "Output Directory: $OUTPUT_DIR"
        echo "Domains File: $DOMAINS_FILE"
        echo "Configured Domains: ${#DOMAINS[@]}"
        echo
        
        show_menu "Main Menu" \
            "Manage Domains" \
            "Certificate Operations" \
            "Install/Check Certbot" \
            "View Logs" \
            "Exit"
        
        read -p "Select option [1-5]: " choice
        
        case "$choice" in
            1) domain_menu ;;
            2) cert_menu ;;
            3) install_certbot ;;
            4) 
                if [[ -f "$LOG_FILE" ]]; then
                    echo
                    log "INFO" "Showing last 20 log entries:"
                    tail -20 "$LOG_FILE"
                else
                    log "WARN" "No log file found"
                fi
                ;;
            5) 
                log "INFO" "Exiting SSL Certificate Manager"
                exit 0 
                ;;
            *) log "ERROR" "Invalid option: $choice" ;;
        esac
        
        if [[ "$choice" != "5" ]]; then
            echo
            read -p "Press Enter to continue..."
        fi
    done
}

# Trap for cleanup
cleanup() {
    log "INFO" "Script interrupted, cleaning up..."
    exit 1
}

trap cleanup INT TERM

# Main execution
main() {
    check_prerequisites
    log "INFO" "Starting $SCRIPT_NAME v$SCRIPT_VERSION"
    main_menu
}

# Run main function
main "$@"
