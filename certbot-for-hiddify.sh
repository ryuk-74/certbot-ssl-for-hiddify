#!/bin/bash

# Enhanced SSL Certificate Manager for Hiddify
# Author: Ryuk-74

set -e

DOMAINS_FILE="domains.txt"
OUTPUT_DIR="/opt/hiddify-manager/ssl"
BACKUP_DIR="/opt/hiddify-manager/ssl/backup"
RATE_LIMIT_FILE="/tmp/certbot_rate_limits.txt"
RENEWAL_SCRIPT="/opt/hiddify-manager/ssl/auto_renew.sh"
RENEWAL_CRON="/etc/cron.d/hiddify-cert-renewal"
LOG_FILE="/var/log/hiddify-certbot.log"

# Create necessary directories
mkdir -p "$OUTPUT_DIR" "$BACKUP_DIR"

# Arrays to keep track of stopped services and killed processes
STOPPED_SERVICES=()
KILLED_PIDS=()

# Rate limiting information
RATE_LIMITS_INFO="
Let's Encrypt Rate Limits:
- Certificates per Registered Domain: 50 per week
- Duplicate Certificate Limit: 5 per week
- Failed Validation Limit: 5 failures per account, per hostname, per hour
- New Account Key Limit: 10 per IP address per 3 hours
- New Orders Limit: 300 per account per 3 hours
- Renewal exemption: Certificates can be renewed 30 days before expiry without counting toward limits
"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Rate limit tracking
track_rate_limit() {
    local domain="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "$timestamp - Certificate request for $domain" >> "$RATE_LIMIT_FILE"
}

# Check recent rate limit usage
check_rate_limits() {
    local domain="$1"
    local current_week=$(date -d "7 days ago" '+%Y-%m-%d')
    
    if [[ -f "$RATE_LIMIT_FILE" ]]; then
        local recent_requests=$(grep -c "$domain" "$RATE_LIMIT_FILE" 2>/dev/null || echo "0")
        local week_requests=$(awk -v domain="$domain" -v cutoff="$current_week" '
            $1 " " $2 >= cutoff && $0 ~ domain { count++ } 
            END { print count+0 }
        ' "$RATE_LIMIT_FILE" 2>/dev/null || echo "0")
        
        if [[ $week_requests -ge 5 ]]; then
            log "[!] WARNING: $week_requests certificate requests for $domain this week (limit: 5 duplicates per week)"
            read -p "Continue anyway? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                return 1
            fi
        fi
    fi
    return 0
}

# Show rate limit information
show_rate_limits() {
    echo "$RATE_LIMITS_INFO"
    
    if [[ -f "$RATE_LIMIT_FILE" ]]; then
        echo "Recent certificate requests:"
        tail -10 "$RATE_LIMIT_FILE" 2>/dev/null || echo "No recent requests logged"
    fi
}

# DNS resolution check
check_dns_resolution() {
    local domain="$1"
    log "[*] Checking DNS resolution for $domain..."
    
    # Check if domain resolves to current server IP
    local domain_ip=$(dig +short "$domain" 2>/dev/null | tail -1)
    local server_ips=($(hostname -I 2>/dev/null || ip addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1'))
    
    if [[ -z "$domain_ip" ]]; then
        log "[!] ERROR: Domain $domain does not resolve to any IP address"
        return 1
    fi
    
    # Check if domain IP matches any of the server IPs
    local ip_match=false
    for server_ip in "${server_ips[@]}"; do
        if [[ "$domain_ip" == "$server_ip" ]]; then
            ip_match=true
            break
        fi
    done
    
    if [[ "$ip_match" == false ]]; then
        log "[!] WARNING: Domain $domain resolves to $domain_ip, but server IPs are: ${server_ips[*]}"
        log "[!] Certificate validation may fail if the domain doesn't point to this server"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return 1
        fi
    else
        log "[✓] DNS resolution check passed for $domain"
    fi
    
    return 0
}

# Certificate backup function
backup_certificate() {
    local domain="$1"
    local backup_timestamp=$(date '+%Y%m%d_%H%M%S')
    local backup_subdir="$BACKUP_DIR/${domain}_${backup_timestamp}"
    
    if [[ -f "$OUTPUT_DIR/$domain.crt" && -f "$OUTPUT_DIR/$domain.crt.key" ]]; then
        log "[*] Backing up existing certificates for $domain..."
        mkdir -p "$backup_subdir"
        
        # Use secure file operations
        (
            umask 077
            cp "$OUTPUT_DIR/$domain.crt" "$backup_subdir/$domain.crt" 2>/dev/null || true
            cp "$OUTPUT_DIR/$domain.crt.key" "$backup_subdir/$domain.crt.key" 2>/dev/null || true
        )
        
        # Also backup from Let's Encrypt directory if available
        if [[ -d "/etc/letsencrypt/live/$domain" ]]; then
            cp -r "/etc/letsencrypt/live/$domain" "$backup_subdir/letsencrypt_live" 2>/dev/null || true
            cp -r "/etc/letsencrypt/archive/$domain" "$backup_subdir/letsencrypt_archive" 2>/dev/null || true
        fi
        
        log "[✓] Certificates backed up to $backup_subdir"
        
        # Keep only last 5 backups per domain
        cleanup_old_backups "$domain"
    else
        log "[i] No existing certificates found for $domain to backup"
    fi
}

# Cleanup old backups
cleanup_old_backups() {
    local domain="$1"
    local backup_count=$(ls -1d "$BACKUP_DIR/${domain}_"* 2>/dev/null | wc -l)
    
    if [[ $backup_count -gt 5 ]]; then
        log "[*] Cleaning up old backups for $domain (keeping last 5)..."
        ls -1td "$BACKUP_DIR/${domain}_"* 2>/dev/null | tail -n +6 | xargs rm -rf
        log "[✓] Old backups cleaned up"
    fi
}

function load_domains() {
    mapfile -t DOMAINS < "$DOMAINS_FILE" 2>/dev/null || DOMAINS=()
}

function save_domains() {
    # Secure file operation
    (
        umask 022
        printf "%s\n" "${DOMAINS[@]}" > "$DOMAINS_FILE"
    )
}

function delete_cert_files() {
    local domain="$1"
    
    # Backup before deletion
    backup_certificate "$domain"
    
    # Secure deletion
    if [[ -f "$OUTPUT_DIR/$domain.crt" ]]; then
        shred -vfz -n 1 "$OUTPUT_DIR/$domain.crt" 2>/dev/null || rm -f "$OUTPUT_DIR/$domain.crt"
    fi
    if [[ -f "$OUTPUT_DIR/$domain.crt.key" ]]; then
        shred -vfz -n 1 "$OUTPUT_DIR/$domain.crt.key" 2>/dev/null || rm -f "$OUTPUT_DIR/$domain.crt.key"
    fi
}

function install_certbot() {
    if command -v certbot >/dev/null 2>&1; then
        log "[✓] Certbot is already installed."
        return
    fi
    log "[*] Installing Certbot..."
    sudo snap install --classic certbot
    log "[✓] Certbot installed."
}
# Automatic renewal mechanism setup
setup_auto_renewal() {
    log "[*] Setting up automatic certificate renewal..."
    
    # Create renewal script
    cat > "$RENEWAL_SCRIPT" << 'EOF'
#!/bin/bash

# Auto-renewal script for Hiddify SSL certificates
LOG_FILE="/var/log/hiddify-certbot.log"
OUTPUT_DIR="/opt/hiddify-manager/ssl"
BACKUP_DIR="/opt/hiddify-manager/ssl/backup"
DOMAINS_FILE="domains.txt"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Load domains
mapfile -t DOMAINS < "$DOMAINS_FILE" 2>/dev/null || DOMAINS=()

log "[*] Starting automatic certificate renewal check..."

for domain in "${DOMAINS[@]}"; do
    if [[ -z "$domain" ]]; then
        continue
    fi
    
    log "[*] Checking certificate expiry for $domain..."
    
    # Check certificate expiry
    cert_file="$OUTPUT_DIR/$domain.crt"
    if [[ -f "$cert_file" ]]; then
        exp_date=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2)
        if [[ -n "$exp_date" ]]; then
            exp_epoch=$(date -d "$exp_date" +%s 2>/dev/null)
            current_epoch=$(date +%s)
            days_until_expiry=$(( (exp_epoch - current_epoch) / 86400 ))
            
            log "[*] Certificate for $domain expires in $days_until_expiry days"
            
            # Renew if less than 30 days until expiry
            if [[ $days_until_expiry -le 30 ]]; then
                log "[*] Certificate for $domain needs renewal (expires in $days_until_expiry days)"
                
                # Backup existing certificate
                backup_timestamp=$(date '+%Y%m%d_%H%M%S')
                backup_subdir="$BACKUP_DIR/${domain}_renewal_${backup_timestamp}"
                mkdir -p "$backup_subdir"
                
                cp "$cert_file" "$backup_subdir/" 2>/dev/null || true
                cp "$OUTPUT_DIR/$domain.crt.key" "$backup_subdir/" 2>/dev/null || true
                
                # Attempt renewal
                if certbot renew --cert-name "$domain" --non-interactive; then
                    log "[✓] Certificate renewed successfully for $domain"
                    
                    # Copy renewed certificates
                    CERT_SRC="/etc/letsencrypt/live/$domain/fullchain.pem"
                    KEY_SRC="/etc/letsencrypt/live/$domain/privkey.pem"
                    
                    if [[ -f "$CERT_SRC" && -f "$KEY_SRC" ]]; then
                        cp "$CERT_SRC" "$OUTPUT_DIR/$domain.crt"
                        cp "$KEY_SRC" "$OUTPUT_DIR/$domain.crt.key"
                        chmod 644 "$OUTPUT_DIR/$domain.crt"
                        chmod 600 "$OUTPUT_DIR/$domain.crt.key"
                        log "[✓] Renewed certificates copied for $domain"
                        
                        # Restart Hiddify services if needed
                        if systemctl is-active --quiet hiddify-panel; then
                            systemctl reload hiddify-panel || systemctl restart hiddify-panel
                            log "[*] Restarted Hiddify panel service"
                        fi
                    else
                        log "[!] Failed to find renewed certificate files for $domain"
                    fi
                else
                    log "[!] Certificate renewal failed for $domain"
                fi
            else
                log "[*] Certificate for $domain is still valid ($days_until_expiry days remaining)"
            fi
        else
            log "[!] Could not read expiry date for $domain certificate"
        fi
    else
        log "[!] Certificate file not found for $domain"
    fi
done

log "[*] Automatic renewal check completed"
EOF

    chmod +x "$RENEWAL_SCRIPT"
    
    # Create cron job for automatic renewal (runs twice daily)
    cat > "$RENEWAL_CRON" << EOF
# Hiddify SSL Certificate Auto-Renewal
# Runs twice daily at 2:30 AM and 2:30 PM
30 2,14 * * * root $RENEWAL_SCRIPT
EOF
    
    log "[✓] Automatic renewal setup completed"
    log "[*] Certificates will be checked for renewal twice daily"
    log "[*] Renewal script: $RENEWAL_SCRIPT"
    log "[*] Cron job: $RENEWAL_CRON"
}

# Remove automatic renewal
remove_auto_renewal() {
    log "[*] Removing automatic renewal setup..."
    
    if [[ -f "$RENEWAL_SCRIPT" ]]; then
        rm -f "$RENEWAL_SCRIPT"
        log "[✓] Renewal script removed"
    fi
    
    if [[ -f "$RENEWAL_CRON" ]]; then
        rm -f "$RENEWAL_CRON"
        log "[✓] Cron job removed"
    fi
    
    log "[✓] Automatic renewal setup removed"
}

# Manual certificate renewal
manual_renewal() {
    local domain="$1"
    
    log "[*] Starting manual renewal for $domain..."
    
    # Check if certificate exists in Let's Encrypt
    if [[ ! -d "/etc/letsencrypt/live/$domain" ]]; then
        log "[!] No Let's Encrypt certificate found for $domain"
        log "[*] Use 'Request Certificate' option instead"
        return 1
    fi
    
    # Backup existing certificate
    backup_certificate "$domain"
    
    # Check DNS resolution before renewal
    if ! check_dns_resolution "$domain"; then
        log "[!] DNS validation failed for $domain"
        return 1
    fi
    
    # Check rate limits
    if ! check_rate_limits "$domain"; then
        log "[!] Rate limit check failed for $domain"
        return 1
    fi
    
    # Stop services using port 80
    stop_port_80_services
    
    # Attempt renewal
    if certbot renew --cert-name "$domain" --non-interactive --force-renewal; then
        log "[✓] Certificate renewed successfully for $domain"
        track_rate_limit "$domain"
        
        # Copy renewed certificates with secure operations
        local CERT_SRC="/etc/letsencrypt/live/$domain/fullchain.pem"
        local KEY_SRC="/etc/letsencrypt/live/$domain/privkey.pem"
        
        if [[ -f "$CERT_SRC" && -f "$KEY_SRC" ]]; then
            (
                umask 022
                cp "$CERT_SRC" "$OUTPUT_DIR/$domain.crt"
            )
            (
                umask 077
                cp "$KEY_SRC" "$OUTPUT_DIR/$domain.crt.key"
            )
            chmod 644 "$OUTPUT_DIR/$domain.crt"
            chmod 600 "$OUTPUT_DIR/$domain.crt.key"
            log "[✓] Renewed certificates copied for $domain"
        else
            log "[!] Failed to find renewed certificate files for $domain"
            restart_stopped_services
            return 1
        fi
    else
        log "[!] Certificate renewal failed for $domain"
        restart_stopped_services
        return 1
    fi
    
    restart_stopped_services
    return 0
}

# Improved function to stop all services/processes using port 80
function stop_port_80_services() {
    log "[*] Checking for services/processes using port 80..."

    # Multiple methods to find processes using port 80
    local pids=()
    
    # Method 1: Using ss command
    local ss_pids=($(ss -ltnp 'sport = :80' 2>/dev/null | awk 'NR>1 && $7 != "" {gsub(/.*pid=/, "", $7); gsub(/,.*/, "", $7); print $7}' | grep -E '^[0-9]+$' | sort -u))
    pids+=("${ss_pids[@]}")
    
    # Method 2: Using netstat as backup
    local netstat_pids=($(netstat -tlnp 2>/dev/null | awk '$4 ~ /:80$/ && $7 != "-" {gsub(/\/.*/, "", $7); print $7}' | grep -E '^[0-9]+$' | sort -u))
    pids+=("${netstat_pids[@]}")
    
    # Method 3: Using lsof as another backup
    local lsof_pids=($(lsof -i :80 -t 2>/dev/null | grep -E '^[0-9]+$' | sort -u))
    pids+=("${lsof_pids[@]}")
    
    # Method 4: Using fuser
    local fuser_pids=($(fuser 80/tcp 2>/dev/null | grep -oE '[0-9]+' | sort -u))
    pids+=("${fuser_pids[@]}")
    
    # Remove duplicates and empty entries
    pids=($(printf "%s\n" "${pids[@]}" | grep -E '^[0-9]+$' | sort -u))

    if [[ ${#pids[@]} -eq 0 ]]; then
        log "[*] No processes found using port 80."
        # Double-check by trying to bind to port 80
        if ! timeout 2 nc -l 80 2>/dev/null; then
            log "[!] Warning: Port 80 might still be in use despite no processes found."
        else
            # Kill the nc process we just started
            pkill -f "nc -l 80" 2>/dev/null || true
            log "[✓] Port 80 confirmed to be free."
        fi
        return
    fi

    log "[*] Found ${#pids[@]} process(es) using port 80: ${pids[*]}"

    for pid in "${pids[@]}"; do
        if ! kill -0 "$pid" 2>/dev/null; then
            log "[i] Process $pid is no longer running."
            continue
        fi

        # Get process information
        local process_info=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
        log "[*] Found process: $process_info (PID: $pid)"

        # Try to find systemd service associated with this PID
        local service_name=""
        service_name=$(systemctl list-units --type=service --state=running --no-legend | awk '{print $1}' | while read -r svc; do
            mainpid=$(systemctl show -p MainPID --value "$svc" 2>/dev/null)
            if [[ "$mainpid" == "$pid" ]]; then
                echo "$svc"
                break
            fi
        done)

        if [[ -n "$service_name" ]]; then
            log "[*] Stopping systemd service $service_name (PID $pid) using port 80..."
            sudo systemctl stop "$service_name" || log "[!] Failed to stop service $service_name"
            STOPPED_SERVICES+=("$service_name")
        else
            log "[*] Killing process $process_info (PID $pid) listening on port 80..."
            sudo kill -TERM "$pid" 2>/dev/null || true
            sleep 2
            if kill -0 "$pid" 2>/dev/null; then
                log "[*] Process still running, sending SIGKILL..."
                sudo kill -KILL "$pid" 2>/dev/null || true
            fi
            KILLED_PIDS+=("$pid")
        fi
    done

    # Wait for port 80 to be freed up, up to 15 seconds
    log "[*] Waiting for port 80 to become free..."
    for i in {1..15}; do
        # Check multiple ways
        if ! ss -ltnp 'sport = :80' 2>/dev/null | grep -q ':80' && \
           ! netstat -tlnp 2>/dev/null | grep -q ':80' && \
           ! lsof -i :80 2>/dev/null | grep -q ':80'; then
            log "[✓] Port 80 is now free."
            return
        fi
        log "[i] Port 80 still in use, waiting... ($i/15)"
        sleep 1
    done

    log "[!] Warning: Port 80 might still be in use after waiting."
    log "[*] Attempting to show what's still using port 80:"
    ss -ltnp 'sport = :80' 2>/dev/null || true
    netstat -tlnp 2>/dev/null | grep ':80' || true
    lsof -i :80 2>/dev/null || true
}
# Restart all previously stopped services; notify about killed PIDs
function restart_stopped_services() {
    log "[*] Restarting previously stopped services..."
    for service in "${STOPPED_SERVICES[@]}"; do
        log "[*] Starting service $service..."
        sudo systemctl start "$service" || log "[!] Failed to restart service $service"
    done

    if [[ ${#KILLED_PIDS[@]} -gt 0 ]]; then
        log "[!] The following processes were killed and cannot be restarted automatically:"
        for pid in "${KILLED_PIDS[@]}"; do
            log "    - PID $pid"
        done
        log "[!] You may need to manually restart these services/applications."
    fi
    
    # Clear arrays for next use
    STOPPED_SERVICES=()
    KILLED_PIDS=()
}

function request_cert() {
    local domain="$1"
    log "[*] Requesting certificate for: $domain"

    # Pre-flight checks
    if ! check_dns_resolution "$domain"; then
        log "[!] DNS validation failed for $domain"
        return 1
    fi
    
    if ! check_rate_limits "$domain"; then
        log "[!] Rate limit check failed for $domain"
        return 1
    fi

    # Backup existing certificate if present
    backup_certificate "$domain"

    stop_port_80_services

    # Add more verbose output for debugging
    log "[*] Attempting to request certificate with Certbot..."
    
    if certbot certonly \
        --standalone \
        --non-interactive \
        --agree-tos \
        --register-unsafely-without-email \
        -d "$domain"; then
        log "[✓] Certificate request successful for $domain"
        track_rate_limit "$domain"
    else
        log "[!] Certificate request failed for $domain"
        log "[*] Checking what might be using port 80:"
        ss -ltnp 'sport = :80' 2>/dev/null || true
        netstat -tlnp 2>/dev/null | grep ':80' || true
        lsof -i :80 2>/dev/null || true
        restart_stopped_services
        return 1
    fi

    restart_stopped_services

    local CERT_SRC="/etc/letsencrypt/live/$domain/fullchain.pem"
    local KEY_SRC="/etc/letsencrypt/live/$domain/privkey.pem"

    if [[ -f "$CERT_SRC" && -f "$KEY_SRC" ]]; then
        # Secure file operations
        (
            umask 022
            cp "$CERT_SRC" "$OUTPUT_DIR/$domain.crt"
        )
        (
            umask 077
            cp "$KEY_SRC" "$OUTPUT_DIR/$domain.crt.key"
        )
        chmod 644 "$OUTPUT_DIR/$domain.crt"
        chmod 600 "$OUTPUT_DIR/$domain.crt.key"
        log "[+] Saved to $OUTPUT_DIR/$domain.crt and $OUTPUT_DIR/$domain.crt.key"
    else
        log "[!] Failed to find cert/key files for $domain"
        return 1
    fi
}

function request_all_certs() {
    local failed_domains=()
    
    for domain in "${DOMAINS[@]}"; do
        if [[ -z "$domain" ]]; then
            continue
        fi
        
        echo ""
        echo "========================================"
        if request_cert "$domain"; then
            log "[✓] Certificate successfully obtained for $domain"
        else
            log "[!] Certificate request failed for $domain"
            failed_domains+=("$domain")
        fi
        echo "========================================"
        echo ""
        
        # Small delay between requests to avoid overwhelming the system
        sleep 2
    done
    
    # Summary report
    if [[ ${#failed_domains[@]} -gt 0 ]]; then
        log "[!] Failed to obtain certificates for: ${failed_domains[*]}"
        log "[*] You may need to check DNS settings or rate limits for these domains"
    else
        log "[✓] All certificates obtained successfully"
    fi
}

function request_single_cert() {
    if [[ ${#DOMAINS[@]} -eq 0 ]]; then
        log "[!] No domains configured. Please add domains first."
        return
    fi
    
    echo "[*] Available domains:"
    for i in "${!DOMAINS[@]}"; do
        echo "$((i+1)). ${DOMAINS[$i]}"
    done
    read -rp "Select domain number: " idx
    idx=$((idx-1))
    if [[ $idx -ge 0 && $idx -lt ${#DOMAINS[@]} ]]; then
        request_cert "${DOMAINS[$idx]}"
    else
        log "[!] Invalid selection."
    fi
}

function add_domain() {
    read -rp "Enter new domain: " new_domain
    # Basic domain validation
    if [[ -z "$new_domain" ]]; then
        log "[!] Domain cannot be empty."
        return
    fi
    
    # Enhanced domain validation
    if [[ ! "$new_domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$ ]]; then
        log "[!] Invalid domain format."
        return
    fi
    
    # Check domain length
    if [[ ${#new_domain} -gt 253 ]]; then
        log "[!] Domain name too long (max 253 characters)."
        return
    fi
    
    # Check if domain already exists
    for existing_domain in "${DOMAINS[@]}"; do
        if [[ "$existing_domain" == "$new_domain" ]]; then
            log "[!] Domain already exists."
            return
        fi
    done
    
    # Optional: DNS pre-check
    read -p "Perform DNS validation before adding? (Y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        if ! check_dns_resolution "$new_domain"; then
            log "[!] DNS validation failed. Domain not added."
            return
        fi
    fi
    
    DOMAINS+=("$new_domain")
    save_domains
    log "[✓] Domain added: $new_domain"
}

function edit_domain() {
    if [[ ${#DOMAINS[@]} -eq 0 ]]; then
        log "[!] No domains configured."
        return
    fi
    
    echo "[*] Current domains:"
    for i in "${!DOMAINS[@]}"; do
        echo "$((i+1)). ${DOMAINS[$i]}"
    done
    read -rp "Select domain number to edit: " idx
    idx=$((idx-1))
    if [[ $idx -ge 0 && $idx -lt ${#DOMAINS[@]} ]]; then
        local old_domain="${DOMAINS[$idx]}"
        read -rp "Enter new value for $old_domain: " new_domain
        if [[ -z "$new_domain" ]]; then
            log "[!] Domain cannot be empty."
            return
        fi
        
        # Validate new domain
        if [[ ! "$new_domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$ ]]; then
            log "[!] Invalid domain format."
            return
        fi
        
        if [[ "$old_domain" != "$new_domain" ]]; then
            # DNS validation for new domain
            if ! check_dns_resolution "$new_domain"; then
                read -p "DNS validation failed. Continue anyway? (y/N): " -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    return
                fi
            fi
            
            DOMAINS[$idx]="$new_domain"
            delete_cert_files "$old_domain"
            save_domains
            log "[*] Domain updated from $old_domain to $new_domain"
            
            read -p "Request certificate for new domain now? (Y/n): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Nn]$ ]]; then
                request_cert "$new_domain"
            fi
        else
            log "[i] No changes made."
        fi
    else
        log "[!] Invalid selection."
    fi
}

function delete_domain() {
    if [[ ${#DOMAINS[@]} -eq 0 ]]; then
        log "[!] No domains configured."
        return
    fi
    
    echo "[*] Current domains:"
    for i in "${!DOMAINS[@]}"; do
        echo "$((i+1)). ${DOMAINS[$i]}"
    done
    read -rp "Select domain number to delete: " idx
    idx=$((idx-1))
    if [[ $idx -ge 0 && $idx -lt ${#DOMAINS[@]} ]]; then
        local domain="${DOMAINS[$idx]}"
        
        echo "[!] This will delete the domain '$domain' and its certificates."
        read -p "Are you sure? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            unset 'DOMAINS[$idx]'
            DOMAINS=("${DOMAINS[@]}")
            delete_cert_files "$domain"
            save_domains
            log "[✓] Domain '$domain' and its certificates removed."
        else
            log "[i] Operation cancelled."
        fi
    else
        log "[!] Invalid selection."
    fi
}

# Certificate status check
function check_cert_status() {
    if [[ ${#DOMAINS[@]} -eq 0 ]]; then
        log "[!] No domains configured."
        return
    fi
    
    echo ""
    echo "===== Certificate Status ====="
    printf "%-30s %-12s %-20s %-10s\n" "Domain" "Status" "Expiry Date" "Days Left"
    echo "--------------------------------------------------------------------------------"
    
    for domain in "${DOMAINS[@]}"; do
        if [[ -z "$domain" ]]; then
            continue
        fi
        
        local cert_file="$OUTPUT_DIR/$domain.crt"
        local status="Missing"
        local expiry_date="N/A"
        local days_left="N/A"
        
        if [[ -f "$cert_file" ]]; then
            if openssl x509 -in "$cert_file" -noout -checkend 0 >/dev/null 2>&1; then
                status="Valid"
                expiry_date=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2)
                if [[ -n "$expiry_date" ]]; then
                    exp_epoch=$(date -d "$expiry_date" +%s 2>/dev/null)
                    current_epoch=$(date +%s)
                    days_left=$(( (exp_epoch - current_epoch) / 86400 ))
                    
                    if [[ $days_left -le 30 ]]; then
                        status="Expires Soon"
                    fi
                    if [[ $days_left -le 7 ]]; then
                        status="Critical"
                    fi
                    if [[ $days_left -lt 0 ]]; then
                        status="Expired"
                    fi
                fi
            else
                status="Invalid/Expired"
            fi
        fi
        
        printf "%-30s %-12s %-20s %-10s\n" "$domain" "$status" "$expiry_date" "$days_left"
    done
    echo ""
}

# Backup management
function backup_menu() {
    while true; do
        echo ""
        echo "===== Backup Management ====="
        echo "1. List Backups"
        echo "2. Restore from Backup"
        echo "3. Clean Old Backups"
        echo "4. Create Manual Backup"
        echo "5. Back"
        echo ""
        read -rp "Select an option: " choice
        
        case $choice in
            1) list_backups ;;
            2) restore_backup ;;
            3) clean_backups ;;
            4) create_manual_backup ;;
            5) return ;;
            *) log "[!] Invalid option." ;;
        esac
    done
}

function list_backups() {
    echo ""
    echo "===== Available Backups ====="
    
    if [[ ! -d "$BACKUP_DIR" ]] || [[ -z "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]]; then
        log "[!] No backups found."
        return
    fi
    
    ls -la "$BACKUP_DIR" | grep "^d" | awk '{print $9, $6, $7, $8}' | grep -v "^\.$\|^\.\.$" | sort
}

function restore_backup() {
    if [[ ! -d "$BACKUP_DIR" ]] || [[ -z "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]]; then
        log "[!] No backups available for restore."
        return
    fi
    
    echo ""
    echo "Available backup directories:"
    ls -1 "$BACKUP_DIR" | grep -E "^[^.]*_[0-9]{8}_[0-9]{6}$" | sort
    echo ""
    read -rp "Enter backup directory name to restore: " backup_name
    
    if [[ ! -d "$BACKUP_DIR/$backup_name" ]]; then
        log "[!] Backup directory not found."
        return
    fi
    
    # Extract domain from backup name
    local domain=$(echo "$backup_name" | sed 's/_[0-9]\{8\}_[0-9]\{6\}$//')
    
    echo "[!] This will restore certificates for domain: $domain"
    echo "[!] Current certificates will be backed up before restore."
    read -p "Continue? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Backup current certificates before restore
        backup_certificate "$domain"
        
        # Restore certificates
        if [[ -f "$BACKUP_DIR/$backup_name/$domain.crt" && -f "$BACKUP_DIR/$backup_name/$domain.crt.key" ]]; then
            (
                umask 022
                cp "$BACKUP_DIR/$backup_name/$domain.crt" "$OUTPUT_DIR/$domain.crt"
            )
            (
                umask 077
                cp "$BACKUP_DIR/$backup_name/$domain.crt.key" "$OUTPUT_DIR/$domain.crt.key"
            )
            chmod 644 "$OUTPUT_DIR/$domain.crt"
            chmod 600 "$OUTPUT_DIR/$domain.crt.key"
            log "[✓] Certificates restored for $domain"
        else
            log "[!] Certificate files not found in backup."
        fi
    else
        log "[i] Restore cancelled."
    fi
}

function clean_backups() {
    if [[ ! -d "$BACKUP_DIR" ]] || [[ -z "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]]; then
        log "[!] No backups found to clean."
        return
    fi
    
    echo ""
    echo "This will remove all backups older than 30 days."
    read -p "Continue? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        find "$BACKUP_DIR" -type d -name "*_[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]_[0-9][0-9][0-9][0-9][0-9][0-9]" -mtime +30 -exec rm -rf {} \; 2>/dev/null
        log "[✓] Old backups cleaned."
    else
        log "[i] Cleanup cancelled."
    fi
}

function create_manual_backup() {
    if [[ ${#DOMAINS[@]} -eq 0 ]]; then
        log "[!] No domains configured."
        return
    fi
    
    echo "[*] Available domains:"
    for i in "${!DOMAINS[@]}"; do
        echo "$((i+1)). ${DOMAINS[$i]}"
    done
    echo "$((${#DOMAINS[@]}+1)). All domains"
    
    read -rp "Select option: " idx
    
    if [[ $idx -eq $((${#DOMAINS[@]}+1)) ]]; then
        # Backup all domains
        for domain in "${DOMAINS[@]}"; do
            backup_certificate "$domain"
        done
        log "[✓] Manual backup created for all domains"
    else
        idx=$((idx-1))
        if [[ $idx -ge 0 && $idx -lt ${#DOMAINS[@]} ]]; then
            backup_certificate "${DOMAINS[$idx]}"
            log "[✓] Manual backup created for ${DOMAINS[$idx]}"
        else
            log "[!] Invalid selection."
        fi
    fi
}

function domain_menu() {
    while true; do
        echo ""
        echo "===== Domain Management ====="
        echo "[*] Current domains: ${#DOMAINS[@]}"
        for i in "${!DOMAINS[@]}"; do
            echo "  $((i+1)). ${DOMAINS[$i]}"
        done
        echo ""
        PS3="Select an option: "
        select opt in "Add Domain" "Edit Domain" "Delete Domain" "Check Certificate Status" "Back"; do
            case $REPLY in
                1) add_domain ; break ;;
                2) edit_domain ; break ;;
                3) delete_domain ; break ;;
                4) check_cert_status ; break ;;
                5) return ;;
                *) log "[!] Invalid option." ;;
            esac
        done
    done
}

function cert_menu() {
    while true; do
        echo ""
        echo "===== Certificate Management ====="
        PS3="Select an option: "
        select opt in "Request All Certificates" "Request for Specific Domain" "Manual Renewal" "Back"; do
            case $REPLY in
                1) request_all_certs ; break ;;
                2) request_single_cert ; break ;;
                3) manual_renewal_menu ; break ;;
                4) return ;;
                *) log "[!] Invalid option." ;;
            esac
        done
    done
}

function manual_renewal_menu() {
    if [[ ${#DOMAINS[@]} -eq 0 ]]; then
        log "[!] No domains configured."
        return
    fi
    
    echo "[*] Available domains for renewal:"
    for i in "${!DOMAINS[@]}"; do
        echo "$((i+1)). ${DOMAINS[$i]}"
    done
    read -rp "Select domain number for renewal: " idx
    idx=$((idx-1))
    if [[ $idx -ge 0 && $idx -lt ${#DOMAINS[@]} ]]; then
        manual_renewal "${DOMAINS[$idx]}"
    else
        log "[!] Invalid selection."
    fi
}

function renewal_menu() {
    while true; do
        echo ""
        echo "===== Automatic Renewal Management ====="
        echo "Current status: $(if [[ -f "$RENEWAL_CRON" ]]; then echo "ENABLED"; else echo "DISABLED"; fi)"
        echo ""
        PS3="Select an option: "
        select opt in "Setup Auto-Renewal" "Remove Auto-Renewal" "Check Renewal Status" "Back"; do
            case $REPLY in
                1) setup_auto_renewal ; break ;;
                2) remove_auto_renewal ; break ;;
                3) check_renewal_status ; break ;;
                4) return ;;
                *) log "[!] Invalid option." ;;
            esac
        done
    done
}

function check_renewal_status() {
    echo ""
    echo "===== Renewal Status ====="
    
    if [[ -f "$RENEWAL_CRON" ]]; then
        echo "[✓] Auto-renewal is ENABLED"
        echo "Schedule: Twice daily at 2:30 AM and 2:30 PM"
        echo "Renewal script: $RENEWAL_SCRIPT"
        echo "Cron job: $RENEWAL_CRON"
    else
        echo "[!] Auto-renewal is DISABLED"
    fi
    
    if [[ -f "$LOG_FILE" ]]; then
        echo ""
        echo "Recent renewal activity:"
        tail -20 "$LOG_FILE" | grep -i "renewal\|renew" || echo "No recent renewal activity"
    fi
}

function main_menu() {
    load_domains
    
    log "[*] Enhanced Certbot SSL Manager started"
    
    while true; do
        echo ""
        echo "===== Enhanced Certbot SSL Manager for Hiddify by Ryuk-74 ====="
        echo "[*] Configured domains: ${#DOMAINS[@]}"
        echo "[*] Auto-renewal: $(if [[ -f "$RENEWAL_CRON" ]]; then echo "ENABLED"; else echo "DISABLED"; fi)"
        echo ""
        PS3="Select an option: "
        select opt in "Manage Domains" "Issue Certificates" "Auto-Renewal Settings" "Backup Management" "Show Rate Limits" "Install Certbot" "Exit"; do
            case $REPLY in
                1) domain_menu ; break ;;
                2) cert_menu ; break ;;
                3) renewal_menu ; break ;;
                4) backup_menu ; break ;;
                5) show_rate_limits ; break ;;
                6) install_certbot ; break ;;
                7) log "[*] Exiting Enhanced Certbot SSL Manager" ; exit 0 ;;
                *) log "[!] Invalid option." ;;
            esac
        done
    done
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "[!] This script must be run as root (use sudo)"
    exit 1
fi

# Initialize log file
log "[*] Starting Enhanced Certbot SSL Manager for Hiddify"

main_menu
