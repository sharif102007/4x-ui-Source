#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
blue='\033[0;34m'
yellow='\033[0;33m'
plain='\033[0m'

xui_folder="${XUI_MAIN_FOLDER:=/usr/local/x-ui}"
xui_service="${XUI_SERVICE:=/etc/systemd/system}"

# Don't edit this config
b_source="${BASH_SOURCE[0]}"
while [ -h "$b_source" ]; do
    b_dir="$(cd -P "$(dirname "$b_source")" > /dev/null 2>&1 && pwd || pwd -P)"
    b_source="$(readlink "$b_source")"
    [[ $b_source != /* ]] && b_source="$b_dir/$b_source"
done
cur_dir="$(cd -P "$(dirname "$b_source")" > /dev/null 2>&1 && pwd || pwd -P)"
script_name=$(basename "$0")

# Check command exist function
_command_exists() {
    type "$1" &> /dev/null
}

# Fail, log and exit script function
_fail() {
    local msg=${1}
    echo -e "${red}${msg}${plain}"
    exit 2
}

# check root
[[ $EUID -ne 0 ]] && _fail "FATAL ERROR: Please run this script with root privilege."

if _command_exists curl; then
    curl_bin=$(which curl)
else
    _fail "ERROR: Command 'curl' not found."
fi

# Check OS and set release variable
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    release=$ID
elif [[ -f /usr/lib/os-release ]]; then
    source /usr/lib/os-release
    release=$ID
else
    _fail "Failed to check the system OS, please contact the author!"
fi
echo "The OS release is: $release"

arch() {
    case "$(uname -m)" in
        x86_64 | x64 | amd64) echo 'amd64' ;;
        i*86 | x86) echo '386' ;;
        armv8* | armv8 | arm64 | aarch64) echo 'arm64' ;;
        armv7* | armv7 | arm) echo 'armv7' ;;
        armv6* | armv6) echo 'armv6' ;;
        armv5* | armv5) echo 'armv5' ;;
        s390x) echo 's390x' ;;
        *) echo -e "${red}Unsupported CPU architecture!${plain}" && rm -f "${cur_dir}/${script_name}" > /dev/null 2>&1 && exit 2 ;;
    esac
}

echo "Arch: $(arch)"

# Simple helpers
is_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && return 0 || return 1
}
is_ipv6() {
    [[ "$1" =~ : ]] && return 0 || return 1
}
is_ip() {
    is_ipv4 "$1" || is_ipv6 "$1"
}
is_domain() {
    [[ "$1" =~ ^([A-Za-z0-9](-*[A-Za-z0-9])*\.)+(xn--[a-z0-9]{2,}|[A-Za-z]{2,})$ ]] && return 0 || return 1
}

# Port helpers
is_port_in_use() {
    local port="$1"
    if command -v ss > /dev/null 2>&1; then
        ss -ltn 2> /dev/null | awk -v p=":${port}$" '$4 ~ p {exit 0} END {exit 1}'
        return
    fi
    if command -v netstat > /dev/null 2>&1; then
        netstat -lnt 2> /dev/null | awk -v p=":${port} " '$4 ~ p {exit 0} END {exit 1}'
        return
    fi
    if command -v lsof > /dev/null 2>&1; then
        lsof -nP -iTCP:${port} -sTCP:LISTEN > /dev/null 2>&1 && return 0
    fi
    return 1
}

gen_random_string() {
    local length="$1"
    openssl rand -base64 $((length * 2)) \
        | tr -dc 'a-zA-Z0-9' \
        | head -c "$length"
}

install_base() {
    echo -e "${green}Refreshing package index and installing dependencies...${plain}"
    echo -e "${yellow}(this can take a minute on a slow mirror - output is shown so you can see progress)${plain}"
    # Output is deliberately NOT redirected to /dev/null. It used to be, which
    # made a slow package index refresh look like the updater had hung.
    #
    # Only the package index is refreshed - never a full system upgrade. The
    # previous `dnf -y update` / `yum -y update` upgraded the entire OS as a side
    # effect of updating the panel, which is both slow and not something a panel
    # updater should decide to do.
    case "${release}" in
        ubuntu | debian | armbian)
            apt-get update || echo -e "${yellow}Warning: apt index refresh reported an error; trying the available package indexes.${plain}"
            apt-get install -y -q cron curl tar tzdata socat ca-certificates openssl nftables iproute2 stunnel4 ||
                echo -e "${yellow}Warning: some optional dependencies could not be installed.${plain}"
            ;;
        fedora | amzn | virtuozzo | rhel | almalinux | rocky | ol)
            dnf -y makecache && dnf install -y -q cronie curl tar tzdata socat ca-certificates openssl nftables iproute stunnel
            ;;
        centos)
            if [[ "${VERSION_ID}" =~ ^7 ]]; then
                yum -y makecache && yum install -y -q cronie curl tar tzdata socat ca-certificates openssl nftables iproute stunnel
            else
                dnf -y makecache && dnf install -y -q cronie curl tar tzdata socat ca-certificates openssl nftables iproute stunnel
            fi
            ;;
        arch | manjaro | parch)
            # Arch does not support partial upgrades, so -Syu is correct here.
            pacman -Syu --noconfirm cronie curl tar tzdata socat ca-certificates openssl nftables iproute2 stunnel
            ;;
        opensuse-tumbleweed | opensuse-leap)
            zypper refresh && zypper -q install -y cron curl tar timezone socat ca-certificates openssl nftables iproute2 stunnel
            ;;
        alpine)
            apk update && apk add dcron curl tar tzdata socat ca-certificates openssl nftables iproute2 stunnel
            ;;
        *)
            apt-get update || echo -e "${yellow}Warning: apt index refresh reported an error; trying the available package indexes.${plain}"
            apt-get install -y -q cron curl tar tzdata socat ca-certificates openssl nftables iproute2 stunnel4 ||
                echo -e "${yellow}Warning: some optional dependencies could not be installed.${plain}"
            ;;
    esac
    echo -e "${green}Dependencies ready.${plain}"
}

# cert_dir_has_valid_cert succeeds when the directory holds a certificate that is
# present, non-empty and not expired.
cert_dir_has_valid_cert() {
    local dir="$1"
    local chain="${dir}/fullchain.pem"
    [[ -s "${chain}" ]] || return 1
    if command -v openssl > /dev/null 2>&1; then
        openssl x509 -in "${chain}" -noout -checkend 0 > /dev/null 2>&1 || return 1
    fi
    return 0
}

# safe_remove_cert_dir removes a certificate directory ONLY when it does not hold
# a usable certificate.
#
# A failed re-issue previously ran `rm -rf` on this path unconditionally, which
# destroyed the certificate the panel and every Xray TLS inbound were already
# using. That is why Xray began failing with "no such file or directory" after an
# update and kept failing until SSL was set up again by hand. A failed attempt to
# get a new certificate must never cost you the working one.
safe_remove_cert_dir() {
    local dir="$1"
    [[ -z "${dir}" || "${dir}" == "/" || "${dir}" == "/root/cert" ]] && return 0
    if cert_dir_has_valid_cert "${dir}"; then
        echo -e "${yellow}Keeping the existing certificate in ${dir} - the new request failed but the current one is still valid.${plain}"
        return 0
    fi
    rm -rf "${dir}" 2> /dev/null || true
    return 0
}

install_acme() {
    echo -e "${green}Installing acme.sh for SSL certificate management...${plain}"
    cd ~ || return 1
    curl -s https://get.acme.sh | sh > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "${red}Failed to install acme.sh${plain}"
        return 1
    else
        echo -e "${green}acme.sh installed successfully${plain}"
    fi
    return 0
}

setup_ssl_certificate() {
    local domain="$1"
    local server_ip="$2"
    local existing_port="$3"
    local existing_webBasePath="$4"

    echo -e "${green}Setting up SSL certificate...${plain}"

    # Check if acme.sh is installed
    if ! command -v ~/.acme.sh/acme.sh &> /dev/null; then
        install_acme
        if [ $? -ne 0 ]; then
            echo -e "${yellow}Failed to install acme.sh, skipping SSL setup${plain}"
            return 1
        fi
    fi

    # Create certificate directory
    local certPath="/root/cert/${domain}"
    mkdir -p "$certPath"

    # Issue certificate
    echo -e "${green}Issuing SSL certificate for ${domain}...${plain}"
    echo -e "${yellow}Note: Port 80 must be open and accessible from the internet${plain}"

    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt --force > /dev/null 2>&1
    ~/.acme.sh/acme.sh --issue -d ${domain} --standalone --httpport 80

    if [ $? -ne 0 ]; then
        echo -e "${yellow}Failed to issue certificate for ${domain}${plain}"
        echo -e "${yellow}Please ensure port 80 is open and try again later with: x-ui${plain}"
        rm -rf ~/.acme.sh/${domain} 2> /dev/null
        safe_remove_cert_dir "$certPath"
        return 1
    fi

    # Install certificate
    ~/.acme.sh/acme.sh --installcert -d ${domain} \
        --key-file /root/cert/${domain}/privkey.pem \
        --fullchain-file /root/cert/${domain}/fullchain.pem \
        --reloadcmd "systemctl restart x-ui" > /dev/null 2>&1

    if [ $? -ne 0 ]; then
        echo -e "${yellow}Failed to install certificate${plain}"
        return 1
    fi

    # Enable auto-renew
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade > /dev/null 2>&1
    chmod 600 $certPath/privkey.pem 2> /dev/null
    chmod 644 $certPath/fullchain.pem 2> /dev/null

    # Set certificate for panel
    local webCertFile="/root/cert/${domain}/fullchain.pem"
    local webKeyFile="/root/cert/${domain}/privkey.pem"

    if [[ -f "$webCertFile" && -f "$webKeyFile" ]]; then
        ${xui_folder}/x-ui cert -webCert "$webCertFile" -webCertKey "$webKeyFile" > /dev/null 2>&1
        echo -e "${green}SSL certificate installed and configured successfully!${plain}"
        return 0
    else
        echo -e "${yellow}Certificate files not found${plain}"
        return 1
    fi
}

# Issue Let's Encrypt IP certificate with shortlived profile (~6 days validity)
# Requires acme.sh and port 80 open for HTTP-01 challenge
setup_ip_certificate() {
    local ipv4="$1"
    local ipv6="$2" # optional

    echo -e "${green}Setting up Let's Encrypt IP certificate (shortlived profile)...${plain}"
    echo -e "${yellow}Note: IP certificates are valid for ~6 days and will auto-renew.${plain}"
    echo -e "${yellow}Default listener is port 80. If you choose another port, ensure external port 80 forwards to it.${plain}"

    # Check for acme.sh
    if ! command -v ~/.acme.sh/acme.sh &> /dev/null; then
        install_acme
        if [ $? -ne 0 ]; then
            echo -e "${red}Failed to install acme.sh${plain}"
            return 1
        fi
    fi

    # Validate IP address
    if [[ -z "$ipv4" ]]; then
        echo -e "${red}IPv4 address is required${plain}"
        return 1
    fi

    if ! is_ipv4 "$ipv4"; then
        echo -e "${red}Invalid IPv4 address: $ipv4${plain}"
        return 1
    fi

    # Create certificate directory
    local certDir="/root/cert/ip"
    mkdir -p "$certDir"

    # Build domain arguments
    local domain_args="-d ${ipv4}"
    if [[ -n "$ipv6" ]] && is_ipv6 "$ipv6"; then
        domain_args="${domain_args} -d ${ipv6}"
        echo -e "${green}Including IPv6 address: ${ipv6}${plain}"
    fi

    # Set reload command for auto-renewal (add || true so it doesn't fail if service stopped)
    local reloadCmd="systemctl restart x-ui 2>/dev/null || rc-service x-ui restart 2>/dev/null || true"

    # Choose port for HTTP-01 listener (default 80, prompt override)
    local WebPort=""
    read -rp "Port to use for ACME HTTP-01 listener (default 80): " WebPort
    WebPort="${WebPort:-80}"
    if ! [[ "${WebPort}" =~ ^[0-9]+$ ]] || ((WebPort < 1 || WebPort > 65535)); then
        echo -e "${red}Invalid port provided. Falling back to 80.${plain}"
        WebPort=80
    fi
    echo -e "${green}Using port ${WebPort} for standalone validation.${plain}"
    if [[ "${WebPort}" -ne 80 ]]; then
        echo -e "${yellow}Reminder: Let's Encrypt still connects on port 80; forward external port 80 to ${WebPort}.${plain}"
    fi

    # Ensure chosen port is available
    while true; do
        if is_port_in_use "${WebPort}"; then
            echo -e "${yellow}Port ${WebPort} is currently in use.${plain}"

            local alt_port=""
            read -rp "Enter another port for acme.sh standalone listener (leave empty to abort): " alt_port
            alt_port="${alt_port// /}"
            if [[ -z "${alt_port}" ]]; then
                echo -e "${red}Port ${WebPort} is busy; cannot proceed.${plain}"
                return 1
            fi
            if ! [[ "${alt_port}" =~ ^[0-9]+$ ]] || ((alt_port < 1 || alt_port > 65535)); then
                echo -e "${red}Invalid port provided.${plain}"
                return 1
            fi
            WebPort="${alt_port}"
            continue
        else
            echo -e "${green}Port ${WebPort} is free and ready for standalone validation.${plain}"
            break
        fi
    done

    # Issue certificate with shortlived profile
    echo -e "${green}Issuing IP certificate for ${ipv4}...${plain}"
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt --force > /dev/null 2>&1

    ~/.acme.sh/acme.sh --issue \
        ${domain_args} \
        --standalone \
        --server letsencrypt \
        --certificate-profile shortlived \
        --days 6 \
        --httpport ${WebPort}

    if [ $? -ne 0 ]; then
        echo -e "${red}Failed to issue IP certificate${plain}"
        echo -e "${yellow}Please ensure port ${WebPort} is reachable (or forwarded from external port 80)${plain}"
        # Cleanup acme.sh data for both IPv4 and IPv6 if specified
        rm -rf ~/.acme.sh/${ipv4} 2> /dev/null
        [[ -n "$ipv6" ]] && rm -rf ~/.acme.sh/${ipv6} 2> /dev/null
        safe_remove_cert_dir "${certDir}"
        return 1
    fi

    echo -e "${green}Certificate issued successfully, installing...${plain}"

    # Install certificate
    # Note: acme.sh may report "Reload error" and exit non-zero if reloadcmd fails,
    # but the cert files are still installed. We check for files instead of exit code.
    ~/.acme.sh/acme.sh --installcert -d ${ipv4} \
        --key-file "${certDir}/privkey.pem" \
        --fullchain-file "${certDir}/fullchain.pem" \
        --reloadcmd "${reloadCmd}" 2>&1 || true

    # Verify certificate files exist (don't rely on exit code - reloadcmd failure causes non-zero)
    if [[ ! -f "${certDir}/fullchain.pem" || ! -f "${certDir}/privkey.pem" ]]; then
        echo -e "${red}Certificate files not found after installation${plain}"
        # Cleanup acme.sh data for both IPv4 and IPv6 if specified
        rm -rf ~/.acme.sh/${ipv4} 2> /dev/null
        [[ -n "$ipv6" ]] && rm -rf ~/.acme.sh/${ipv6} 2> /dev/null
        safe_remove_cert_dir "${certDir}"
        return 1
    fi

    echo -e "${green}Certificate files installed successfully${plain}"

    # Enable auto-upgrade for acme.sh (ensures cron job runs)
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade > /dev/null 2>&1

    chmod 600 ${certDir}/privkey.pem 2> /dev/null
    chmod 644 ${certDir}/fullchain.pem 2> /dev/null

    # Configure panel to use the certificate
    echo -e "${green}Setting certificate paths for the panel...${plain}"
    ${xui_folder}/x-ui cert -webCert "${certDir}/fullchain.pem" -webCertKey "${certDir}/privkey.pem"
    if [ $? -ne 0 ]; then
        echo -e "${yellow}Warning: Could not set certificate paths automatically.${plain}"
        echo -e "${yellow}You may need to set them manually in the panel settings.${plain}"
        echo -e "${yellow}Cert path: ${certDir}/fullchain.pem${plain}"
        echo -e "${yellow}Key path: ${certDir}/privkey.pem${plain}"
    else
        echo -e "${green}Certificate paths set successfully!${plain}"
    fi

    echo -e "${green}IP certificate installed and configured successfully!${plain}"
    echo -e "${green}Certificate valid for ~6 days, auto-renews via acme.sh cron job.${plain}"
    echo -e "${yellow}Panel will automatically restart after each renewal.${plain}"
    return 0
}

# Comprehensive manual SSL certificate issuance via acme.sh
ssl_cert_issue() {
    local existing_webBasePath=$(${xui_folder}/x-ui setting -show true | grep 'webBasePath:' | awk -F': ' '{print $2}' | tr -d '[:space:]' | sed 's#^/##')
    local existing_port=$(${xui_folder}/x-ui setting -show true | grep 'port:' | awk -F': ' '{print $2}' | tr -d '[:space:]')

    # check for acme.sh first
    if ! command -v ~/.acme.sh/acme.sh &> /dev/null; then
        echo "acme.sh could not be found. Installing now..."
        cd ~ || return 1
        curl -s https://get.acme.sh | sh
        if [ $? -ne 0 ]; then
            echo -e "${red}Failed to install acme.sh${plain}"
            return 1
        else
            echo -e "${green}acme.sh installed successfully${plain}"
        fi
    fi

    # get the domain here, and we need to verify it
    local domain=""
    while true; do
        read -rp "Please enter your domain name: " domain
        domain="${domain// /}" # Trim whitespace

        if [[ -z "$domain" ]]; then
            echo -e "${red}Domain name cannot be empty. Please try again.${plain}"
            continue
        fi

        if ! is_domain "$domain"; then
            echo -e "${red}Invalid domain format: ${domain}. Please enter a valid domain name.${plain}"
            continue
        fi

        break
    done
    echo -e "${green}Your domain is: ${domain}. Checking existing ACME certificates...${plain}"
    SSL_ISSUED_DOMAIN="${domain}"

    # detect existing certificate and reuse it if present
    local cert_exists=0
    local cert_list=""
    cert_list=$(run_with_timeout 10 ~/.acme.sh/acme.sh --list 2> /dev/null || true)
    if echo "${cert_list}" | awk '{print $1}' | grep -Fxq "${domain}"; then
        cert_exists=1
        local certInfo
        certInfo=$(echo "${cert_list}" | grep -F "${domain}" | head -1)
        echo -e "${yellow}Existing certificate found for ${domain}, will reuse it.${plain}"
        [[ -n "${certInfo}" ]] && echo "$certInfo"
    else
        echo -e "${green}Your domain is ready for issuing certificates now...${plain}"
    fi

    # create a directory for the certificate
    certPath="/root/cert/${domain}"
    # Do not wipe an existing certificate directory before requesting a new one:
    # if the request then fails there is nothing left to fall back to, and the
    # panel plus every Xray TLS inbound pointing here break. acme.sh
    # --installcert overwrites the files on success, so creating the directory is
    # all that is needed.
    mkdir -p "$certPath"

    # get the port number for the standalone server
    local WebPort=80
    read -rp "Please choose which port to use (default is 80): " WebPort
    if [[ ${WebPort} -gt 65535 || ${WebPort} -lt 1 ]]; then
        echo -e "${yellow}Your input ${WebPort} is invalid, will use default port 80.${plain}"
        WebPort=80
    fi
    echo -e "${green}Will use port: ${WebPort} to issue certificates. Please make sure this port is open.${plain}"

    # Stop panel temporarily
    echo -e "${yellow}Stopping panel temporarily...${plain}"
    systemctl stop x-ui 2> /dev/null || rc-service x-ui stop 2> /dev/null

    if [[ ${cert_exists} -eq 0 ]]; then
        # issue the certificate
        run_with_timeout 60 ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt --force
        run_with_timeout 300 ~/.acme.sh/acme.sh --issue -d "${domain}" --standalone --httpport "${WebPort}"
        if [ $? -ne 0 ]; then
            echo -e "${red}Issuing certificate failed, please check logs.${plain}"
            rm -rf ~/.acme.sh/${domain}
            systemctl start x-ui 2> /dev/null || rc-service x-ui start 2> /dev/null
            return 1
        else
            echo -e "${green}Issuing certificate succeeded, installing certificates...${plain}"
        fi
    else
        echo -e "${green}Using existing certificate, installing certificates...${plain}"
    fi

    # Setup reload command
    reloadCmd="systemctl restart x-ui || rc-service x-ui restart"
    echo -e "${green}Default --reloadcmd for ACME is: ${yellow}systemctl restart x-ui || rc-service x-ui restart${plain}"
    echo -e "${green}This command will run on every certificate issue and renew.${plain}"
    read -rp "Would you like to modify --reloadcmd for ACME? (y/n): " setReloadcmd
    if [[ "$setReloadcmd" == "y" || "$setReloadcmd" == "Y" ]]; then
        echo -e "\n${green}\t1.${plain} Preset: systemctl reload nginx ; systemctl restart x-ui"
        echo -e "${green}\t2.${plain} Input your own command"
        echo -e "${green}\t0.${plain} Keep default reloadcmd"
        read -rp "Choose an option: " choice
        case "$choice" in
            1)
                echo -e "${green}Reloadcmd is: systemctl reload nginx ; systemctl restart x-ui${plain}"
                reloadCmd="systemctl reload nginx ; systemctl restart x-ui"
                ;;
            2)
                echo -e "${yellow}It's recommended to put x-ui restart at the end${plain}"
                read -rp "Please enter your custom reloadcmd: " reloadCmd
                echo -e "${green}Reloadcmd is: ${reloadCmd}${plain}"
                ;;
            *)
                echo -e "${green}Keeping default reloadcmd${plain}"
                ;;
        esac
    fi

    # install the certificate
    local installOutput=""
    installOutput=$(~/.acme.sh/acme.sh --installcert -d ${domain} \
        --key-file /root/cert/${domain}/privkey.pem \
        --fullchain-file /root/cert/${domain}/fullchain.pem --reloadcmd "${reloadCmd}" 2>&1)
    local installRc=$?
    echo "${installOutput}"

    local installWroteFiles=0
    if echo "${installOutput}" | grep -q "Installing key to:" && echo "${installOutput}" | grep -q "Installing full chain to:"; then
        installWroteFiles=1
    fi

    if [[ -f "/root/cert/${domain}/privkey.pem" && -f "/root/cert/${domain}/fullchain.pem" && (${installRc} -eq 0 || ${installWroteFiles} -eq 1) ]]; then
        echo -e "${green}Installing certificate succeeded, enabling auto renew...${plain}"
    else
        echo -e "${red}Installing certificate failed, exiting.${plain}"
        if [[ ${cert_exists} -eq 0 ]]; then
            rm -rf ~/.acme.sh/${domain}
        fi
        systemctl start x-ui 2> /dev/null || rc-service x-ui start 2> /dev/null
        return 1
    fi

    # enable auto-renew
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade
    if [ $? -ne 0 ]; then
        echo -e "${yellow}Auto renew setup had issues, certificate details:${plain}"
        ls -lah /root/cert/${domain}/
        chmod 600 $certPath/privkey.pem
        chmod 644 $certPath/fullchain.pem
    else
        echo -e "${green}Auto renew succeeded, certificate details:${plain}"
        ls -lah /root/cert/${domain}/
        chmod 600 $certPath/privkey.pem
        chmod 644 $certPath/fullchain.pem
    fi

    # Restart panel
    systemctl start x-ui 2> /dev/null || rc-service x-ui start 2> /dev/null

    # Prompt user to set panel paths after successful certificate installation
    read -rp "Would you like to set this certificate for the panel? (y/n): " setPanel
    if [[ "$setPanel" == "y" || "$setPanel" == "Y" ]]; then
        local webCertFile="/root/cert/${domain}/fullchain.pem"
        local webKeyFile="/root/cert/${domain}/privkey.pem"

        if [[ -f "$webCertFile" && -f "$webKeyFile" ]]; then
            ${xui_folder}/x-ui cert -webCert "$webCertFile" -webCertKey "$webKeyFile"
            echo -e "${green}Certificate paths set for the panel${plain}"
            echo -e "${green}Certificate File: $webCertFile${plain}"
            echo -e "${green}Private Key File: $webKeyFile${plain}"
            echo ""
            echo -e "${green}Access URL: https://${domain}:${existing_port}/${existing_webBasePath}${plain}"
            echo -e "${yellow}Panel will restart to apply SSL certificate...${plain}"
            systemctl restart x-ui 2> /dev/null || rc-service x-ui restart 2> /dev/null
        else
            echo -e "${red}Error: Certificate or private key file not found for domain: $domain.${plain}"
        fi
    else
        echo -e "${yellow}Skipping panel path setting.${plain}"
    fi

    return 0
}
# Unified interactive SSL setup (domain or IP)
# Sets global `SSL_HOST` to the chosen domain/IP
prompt_and_setup_ssl() {
    local panel_port="$1"
    local web_base_path="$2" # expected without leading slash
    local server_ip="$3"

    local ssl_choice=""

    echo -e "${yellow}Choose SSL certificate setup method:${plain}"
    echo -e "${green}1.${plain} Let's Encrypt for Domain (90-day validity, auto-renews)"
    echo -e "${green}2.${plain} Let's Encrypt for IP Address (6-day validity, auto-renews)"
    echo -e "${green}3.${plain} Custom SSL Certificate (Path to existing files)"
    echo -e "${blue}Note:${plain} Options 1 & 2 require port 80 open. Option 3 requires manual paths."
    read -rp "Choose an option (default 2 for IP): " ssl_choice
    ssl_choice="${ssl_choice// /}" # Trim whitespace

    # Default to 2 (IP cert) if input is empty or invalid (not 1 or 3)
    if [[ "$ssl_choice" != "1" && "$ssl_choice" != "3" ]]; then
        ssl_choice="2"
    fi

    case "$ssl_choice" in
        1)
            # User chose Let's Encrypt domain option
            echo -e "${green}Using Let's Encrypt for domain certificate...${plain}"
            if ssl_cert_issue; then
                local cert_domain="${SSL_ISSUED_DOMAIN}"
                if [[ -z "${cert_domain}" ]]; then
                    cert_domain=$(run_with_timeout 10 ~/.acme.sh/acme.sh --list 2> /dev/null | tail -1 | awk '{print $1}')
                fi

                if [[ -n "${cert_domain}" ]]; then
                    SSL_HOST="${cert_domain}"
                    echo -e "${green}✓ SSL certificate configured successfully with domain: ${cert_domain}${plain}"
                else
                    echo -e "${yellow}SSL setup may have completed, but domain extraction failed${plain}"
                    SSL_HOST="${server_ip}"
                fi
            else
                echo -e "${red}SSL certificate setup failed for domain mode.${plain}"
                SSL_HOST="${server_ip}"
            fi
            ;;
        2)
            # User chose Let's Encrypt IP certificate option
            echo -e "${green}Using Let's Encrypt for IP certificate (shortlived profile)...${plain}"

            # Ask for optional IPv6
            local ipv6_addr=""
            read -rp "Do you have an IPv6 address to include? (leave empty to skip): " ipv6_addr
            ipv6_addr="${ipv6_addr// /}" # Trim whitespace

            # Stop panel if running (port 80 needed)
            if [[ $release == "alpine" ]]; then
                rc-service x-ui stop > /dev/null 2>&1
            else
                systemctl stop x-ui > /dev/null 2>&1
            fi

            setup_ip_certificate "${server_ip}" "${ipv6_addr}"
            if [ $? -eq 0 ]; then
                SSL_HOST="${server_ip}"
                echo -e "${green}✓ Let's Encrypt IP certificate configured successfully${plain}"
            else
                echo -e "${red}✗ IP certificate setup failed. Please check port 80 is open.${plain}"
                SSL_HOST="${server_ip}"
            fi

            # Restart panel after SSL is configured (restart applies new cert settings)
            if [[ $release == "alpine" ]]; then
                rc-service x-ui restart > /dev/null 2>&1
            else
                systemctl restart x-ui > /dev/null 2>&1
            fi

            ;;
        3)
            # User chose Custom Paths (User Provided) option
            echo -e "${green}Using custom existing certificate...${plain}"
            local custom_cert=""
            local custom_key=""
            local custom_domain=""

            # 3.1 Request Domain to compose Panel URL later
            read -rp "Please enter domain name certificate issued for: " custom_domain
            custom_domain="${custom_domain// /}" # Remove spaces

            # 3.2 Loop for Certificate Path
            while true; do
                read -rp "Input certificate path (keywords: .crt / fullchain): " custom_cert
                # Strip quotes if present
                custom_cert=$(echo "$custom_cert" | tr -d '"' | tr -d "'")

                if [[ -f "$custom_cert" && -r "$custom_cert" && -s "$custom_cert" ]]; then
                    break
                elif [[ ! -f "$custom_cert" ]]; then
                    echo -e "${red}Error: File does not exist! Try again.${plain}"
                elif [[ ! -r "$custom_cert" ]]; then
                    echo -e "${red}Error: File exists but is not readable (check permissions)!${plain}"
                else
                    echo -e "${red}Error: File is empty!${plain}"
                fi
            done

            # 3.3 Loop for Private Key Path
            while true; do
                read -rp "Input private key path (keywords: .key / privatekey): " custom_key
                # Strip quotes if present
                custom_key=$(echo "$custom_key" | tr -d '"' | tr -d "'")

                if [[ -f "$custom_key" && -r "$custom_key" && -s "$custom_key" ]]; then
                    break
                elif [[ ! -f "$custom_key" ]]; then
                    echo -e "${red}Error: File does not exist! Try again.${plain}"
                elif [[ ! -r "$custom_key" ]]; then
                    echo -e "${red}Error: File exists but is not readable (check permissions)!${plain}"
                else
                    echo -e "${red}Error: File is empty!${plain}"
                fi
            done

            # 3.4 Apply Settings via x-ui binary
            ${xui_folder}/x-ui cert -webCert "$custom_cert" -webCertKey "$custom_key" > /dev/null 2>&1

            # Set SSL_HOST for composing Panel URL
            if [[ -n "$custom_domain" ]]; then
                SSL_HOST="$custom_domain"
            else
                SSL_HOST="${server_ip}"
            fi

            echo -e "${green}✓ Custom certificate paths applied.${plain}"
            echo -e "${yellow}Note: You are responsible for renewing these files externally.${plain}"

            systemctl restart x-ui > /dev/null 2>&1 || rc-service x-ui restart > /dev/null 2>&1
            ;;
        *)
            echo -e "${red}Invalid option. Skipping SSL setup.${plain}"
            SSL_HOST="${server_ip}"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Inbound certificate repair
# ---------------------------------------------------------------------------
#
# config_after_update only ever looked at the *panel's* certificate. If that was
# configured it printed "SSL certificate is already configured" and stopped -
# nothing ever checked the certificates the Xray inbounds point at. So a domain
# cert that expired or was deleted stayed broken across every update, Xray
# refused to start, and the only visible symptom was "xray state: Not Running".
#
# This closes that gap: after the panel section, every certificate path
# referenced by the generated Xray config is checked, and any missing one is
# re-issued without prompting.
#
# Safety rules, because this runs inside an unattended update:
#   * never prompts - an update must not block waiting for input
#   * every acme.sh call is wrapped in a timeout so it cannot hang the update
#   * the panel is always brought back up, including on failure
#   * a certificate that already exists is never touched or overwritten
#   * set XUI_SKIP_CERT_REPAIR=1 to disable this step entirely
run_with_timeout() {
    local secs="$1"
    shift
    if command -v timeout > /dev/null 2>&1; then
        timeout "${secs}" "$@"
    else
        "$@"
    fi
}

ensure_panel_running() {
    if command -v systemctl > /dev/null 2>&1; then
        systemctl is-active --quiet x-ui 2> /dev/null || systemctl start x-ui > /dev/null 2>&1 || true
    else
        rc-service x-ui status > /dev/null 2>&1 || rc-service x-ui start > /dev/null 2>&1 || true
    fi
}

port80_holder() {
    ss -ltnp 2> /dev/null | awk '$4 ~ /:80$/ {print $NF}' | head -1
}

cf_credentials_present() {
    [[ -n "${CF_Token:-}" || -n "${CF_Key:-}" ]] && return 0
    grep -qs 'SAVED_CF_Token\|SAVED_CF_Key' "${HOME}/.acme.sh/account.conf" && return 0
    return 1
}

reissue_cert_unattended() {
    # $1 domain, $2 fullchain destination, $3 private-key destination.
    #
    # The destinations come from the Xray config, NOT from a fixed
    # /root/cert/<domain>/ layout. Writing to the conventional path while the
    # inbound points somewhere else produced the worst possible outcome: a
    # certificate issued, "success" reported, and the inbound still dead.
    local domain="$1"
    local fullchain="$2"
    local keyfile="$3"
    local acme="${HOME}/.acme.sh/acme.sh"
    local holder=""

    if [[ -z "${domain}" || -z "${fullchain}" || -z "${keyfile}" ]]; then
        echo -e "${red}  internal error: missing certificate destination${plain}"
        return 1
    fi

    if [[ ! -x "${acme}" ]]; then
        install_acme > /dev/null 2>&1 || true
    fi
    if [[ ! -x "${acme}" ]]; then
        echo -e "${red}  acme.sh is not available, cannot issue ${domain}${plain}"
        return 1
    fi

    mkdir -p "$(dirname "${fullchain}")" "$(dirname "${keyfile}")"
    run_with_timeout 60 "${acme}" --set-default-ca --server letsencrypt > /dev/null 2>&1 || true

    if cf_credentials_present; then
        echo -e "${green}  Using Cloudflare DNS-01 (no port needed)${plain}"
        run_with_timeout 300 "${acme}" --issue --dns dns_cf -d "${domain}" || true
    else
        holder="$(port80_holder)"
        if [[ -z "${holder}" ]]; then
            echo -e "${green}  Port 80 free, using standalone HTTP-01${plain}"
            run_with_timeout 300 "${acme}" --issue -d "${domain}" --standalone --httpport 80 || true
        elif [[ "${holder}" == *x-ui* || "${holder}" == *sshd* || "${holder}" == *stunnel* ]]; then
            echo -e "${yellow}  Port 80 held by the panel; pausing it for the challenge${plain}"
            if command -v systemctl > /dev/null 2>&1; then
                systemctl stop x-ui > /dev/null 2>&1 || true
            else
                rc-service x-ui stop > /dev/null 2>&1 || true
            fi
            sleep 2
            run_with_timeout 300 "${acme}" --issue -d "${domain}" --standalone --httpport 80 || true
            ensure_panel_running
        else
            echo -e "${red}  Port 80 is used by an unrelated process: ${holder}${plain}"
            echo -e "${yellow}  Configure Cloudflare DNS-01 instead:${plain}"
            echo -e "${yellow}    export CF_Token=<token> && x-ui ssl auto ${domain}${plain}"
            return 1
        fi
    fi

    # acme.sh exits non-zero when the reload command fails even though the files
    # were written, so success is decided by looking at the files.
    run_with_timeout 120 "${acme}" --installcert -d "${domain}" \
        --key-file "${keyfile}" \
        --fullchain-file "${fullchain}" \
        --reloadcmd "systemctl restart x-ui 2>/dev/null || rc-service x-ui restart 2>/dev/null" > /dev/null 2>&1 || true

    if [[ -s "${fullchain}" && -s "${keyfile}" ]]; then
        chmod 600 "${keyfile}" 2> /dev/null || true
        echo -e "${green}  Issued: ${fullchain}${plain}"
        return 0
    fi

    echo -e "${red}  Could not issue a certificate for ${domain}${plain}"
    echo -e "${yellow}  See ${HOME}/.acme.sh/acme.sh.log, then run: x-ui ssl auto ${domain}${plain}"
    return 1
}

repair_inbound_certificates() {
    if [[ "${XUI_SKIP_CERT_REPAIR:-0}" == "1" ]]; then
        echo -e "${yellow}Inbound certificate repair skipped (XUI_SKIP_CERT_REPAIR=1).${plain}"
        return 0
    fi

    local cfg="${xui_folder}/bin/config.json"
    [[ -f "${cfg}" ]] || return 0

    # "kind|path" for every certificate reference, so a missing file can be
    # traced back to the exact destination the inbound expects.
    local mapping
    mapping=$(grep -oE '"(certificateFile|keyFile)"[[:space:]]*:[[:space:]]*"[^"]+"' "${cfg}" 2> /dev/null \
        | sed -E 's/^"([a-zA-Z]+)"[[:space:]]*:[[:space:]]*"(.*)"$/\1|\2/' | sort -u)
    [[ -n "${mapping}" ]] || return 0

    local missing="" kind path
    while IFS='|' read -r kind path; do
        [[ -z "${path}" ]] && continue
        [[ -s "${path}" ]] && continue
        missing+="${path}"$'\n'
    done <<< "${mapping}"

    if [[ -z "${missing}" ]]; then
        echo -e "${green}All inbound TLS certificates are present.${plain}"
        return 0
    fi

    echo ""
    echo -e "${yellow}Some Xray inbounds point at certificate files that do not exist:${plain}"
    echo "${missing}" | sed '/^$/d;s/^/  /'
    echo -e "${yellow}Attempting to re-issue them automatically...${plain}"

    local dirs
    dirs=$(echo "${missing}" | sed '/^$/d' | xargs -r -n1 dirname | sort -u)

    local dir domain fullchain keyfile repaired=0 failed=0
    while IFS= read -r dir; do
        [[ -z "${dir}" ]] && continue
        domain=$(basename "${dir}")

        if ! is_domain "${domain}"; then
            echo -e "${yellow}  Skipping '${dir}': '${domain}' is not a domain name.${plain}"
            echo -e "${yellow}  Point that inbound at a real certificate, or use a self-signed one.${plain}"
            failed=1
            continue
        fi

        # Reuse the exact filenames the config references; fall back to the
        # panel's own naming only when one side is not referenced at all.
        fullchain=$(echo "${mapping}" | awk -F'|' -v d="${dir}/" '$1=="certificateFile" && index($2,d)==1 {print $2; exit}')
        keyfile=$(echo "${mapping}" | awk -F'|' -v d="${dir}/" '$1=="keyFile" && index($2,d)==1 {print $2; exit}')
        [[ -n "${fullchain}" ]] || fullchain="${dir}/fullchain.pem"
        [[ -n "${keyfile}" ]] || keyfile="${dir}/privkey.pem"

        echo -e "${green}Certificate for ${domain}:${plain}"
        if reissue_cert_unattended "${domain}" "${fullchain}" "${keyfile}"; then
            repaired=1
        else
            failed=1
        fi
    done <<< "${dirs}"

    # Whatever happened above, the panel must be running when we leave.
    ensure_panel_running

    if [[ ${repaired} -eq 1 ]]; then
        echo -e "${green}Restarting the panel so Xray picks up the new certificates...${plain}"
        if command -v systemctl > /dev/null 2>&1; then
            systemctl restart x-ui > /dev/null 2>&1 || true
        else
            rc-service x-ui restart > /dev/null 2>&1 || true
        fi
    fi
    if [[ ${failed} -eq 1 ]]; then
        echo -e "${yellow}Some certificates still need attention - the panel is running, but the${plain}"
        echo -e "${yellow}affected inbounds will not start until they are fixed.${plain}"
    fi
    return 0
}

config_after_update() {
    echo -e "${yellow}x-ui settings:${plain}"
    ${xui_folder}/x-ui setting -show true
    ${xui_folder}/x-ui migrate

    # Read the settings once. This used to shell out to the panel binary three
    # separate times, each of which starts a process and opens the database.
    local settings_dump
    settings_dump=$(${xui_folder}/x-ui setting -show true 2> /dev/null)

    # Properly detect empty cert by checking if cert: line exists and has content after it
    local existing_cert=$(${xui_folder}/x-ui setting -getCert true 2> /dev/null | grep 'cert:' | awk -F': ' '{print $2}' | tr -d '[:space:]')
    local existing_port=$(echo "${settings_dump}" | grep -Eo 'port: .+' | awk '{print $2}')
    local existing_webBasePath=$(echo "${settings_dump}" | grep -Eo 'webBasePath: .+' | awk '{print $2}' | sed 's#^/##')

    # Only look up the public IP when it is actually needed, i.e. when there is no
    # certificate and we are about to offer to issue one. Six providers at a 3s
    # timeout each meant up to 18 silent seconds on every single update.
    local server_ip=""
    if [[ -z "${existing_cert}" ]]; then
        local URL_lists=(
            "https://api4.ipify.org"
            "https://ipv4.icanhazip.com"
            "https://4.ident.me"
        )
        for ip_address in "${URL_lists[@]}"; do
            local response=$(curl -s -w "\n%{http_code}" --max-time 3 "${ip_address}" 2> /dev/null)
            local http_code=$(echo "$response" | tail -n1)
            local ip_result=$(echo "$response" | head -n-1 | tr -d '[:space:]')
            if [[ "${http_code}" == "200" && -n "${ip_result}" ]]; then
                server_ip="${ip_result}"
                break
            fi
        done
    fi

    # Handle missing/short webBasePath
    if [[ ${#existing_webBasePath} -lt 4 ]]; then
        echo -e "${yellow}WebBasePath is missing or too short. Generating a new one...${plain}"
        local config_webBasePath=$(gen_random_string 18)
        ${xui_folder}/x-ui setting -webBasePath "${config_webBasePath}"
        existing_webBasePath="${config_webBasePath}"
        echo -e "${green}New WebBasePath: ${config_webBasePath}${plain}"
    fi

    # Check and prompt for SSL if missing
    if [[ -z "$existing_cert" ]]; then
        echo ""
        echo -e "${red}═══════════════════════════════════════════${plain}"
        echo -e "${red}      ⚠ NO SSL CERTIFICATE DETECTED ⚠     ${plain}"
        echo -e "${red}═══════════════════════════════════════════${plain}"
        echo -e "${yellow}For security, SSL certificate is MANDATORY for all panels.${plain}"
        echo -e "${yellow}Let's Encrypt now supports both domains and IP addresses!${plain}"
        echo ""

        if [[ -z "${server_ip}" ]]; then
            echo -e "${red}Failed to detect server IP${plain}"
            echo -e "${yellow}Please configure SSL manually using: x-ui${plain}"
            return
        fi

        # Only prompt when there is a terminal to answer on. Run from cron, a
        # pipe or an automation script, the prompt used to sit there waiting
        # forever and the update looked frozen.
        if [[ ! -t 0 ]]; then
            echo -e "${yellow}Not running interactively - skipping SSL setup.${plain}"
            echo -e "${yellow}Configure it later with: x-ui${plain}"
            return
        fi

        # Prompt and setup SSL (domain or IP)
        prompt_and_setup_ssl "${existing_port}" "${existing_webBasePath}" "${server_ip}"

        echo ""
        echo -e "${green}═══════════════════════════════════════════${plain}"
        echo -e "${green}     Panel Access Information              ${plain}"
        echo -e "${green}═══════════════════════════════════════════${plain}"
        echo -e "${green}Access URL: https://${SSL_HOST}:${existing_port}/${existing_webBasePath}${plain}"
        echo -e "${green}═══════════════════════════════════════════${plain}"
        echo -e "${yellow}⚠ SSL Certificate: Enabled and configured${plain}"
    else
        echo -e "${green}SSL certificate is already configured${plain}"
        # Show access URL with existing certificate
        local cert_domain=$(basename "$(dirname "$existing_cert")")
        echo ""
        echo -e "${green}═══════════════════════════════════════════${plain}"
        echo -e "${green}     Panel Access Information              ${plain}"
        echo -e "${green}═══════════════════════════════════════════${plain}"
        echo -e "${green}Access URL: https://${cert_domain}:${existing_port}/${existing_webBasePath}${plain}"
        echo -e "${green}═══════════════════════════════════════════${plain}"
    fi
}

update_x-ui() {
    cd ${xui_folder%/x-ui}/

    if [ -f "${xui_folder}/x-ui" ]; then
        current_xui_version=$(${xui_folder}/x-ui -v)
        echo -e "${green}Current x-ui version: ${current_xui_version}${plain}"
    else
        _fail "ERROR: Current x-ui version: unknown"
    fi

    echo -e "${green}Downloading new x-ui version...${plain}"

    tag_version=$(${curl_bin} -Ls --connect-timeout 10 --max-time 30 --retry 3 "https://api.github.com/repos/sharif102007/4x-ui/releases/latest" 2> /dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [[ ! -n "$tag_version" ]]; then
        echo -e "${yellow}Trying to fetch version with IPv4...${plain}"
        tag_version=$(${curl_bin} -4 -Ls --connect-timeout 10 --max-time 30 --retry 3 "https://api.github.com/repos/sharif102007/4x-ui/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ ! -n "$tag_version" ]]; then
            _fail "ERROR: Failed to fetch x-ui version, it may be due to GitHub API restrictions, please try it later"
        fi
    fi
    echo -e "Got x-ui latest version: ${tag_version}, beginning the installation..."
    ${curl_bin} -fLR --connect-timeout 15 --max-time 300 --retry 3 --retry-delay 2 -o ${xui_folder}-linux-$(arch).tar.gz https://github.com/sharif102007/4x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz
    if [[ $? -ne 0 ]]; then
        echo -e "${yellow}Trying to fetch version with IPv4...${plain}"
        ${curl_bin} -4fLR --connect-timeout 15 --max-time 300 --retry 3 --retry-delay 2 -o ${xui_folder}-linux-$(arch).tar.gz https://github.com/sharif102007/4x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz
        if [[ $? -ne 0 ]]; then
            _fail "ERROR: Failed to download x-ui, please be sure that your server can access GitHub"
        fi
    fi

    if [[ -e ${xui_folder}/ ]]; then
        echo -e "${green}Stopping x-ui...${plain}"
        if [[ $release == "alpine" ]]; then
            if [ -f "/etc/init.d/x-ui" ]; then
                rc-service x-ui stop > /dev/null 2>&1
                rc-update del x-ui > /dev/null 2>&1
                echo -e "${green}Removing old service unit version...${plain}"
                rm -f /etc/init.d/x-ui > /dev/null 2>&1
            else
                rm x-ui-linux-$(arch).tar.gz -f > /dev/null 2>&1
                _fail "ERROR: x-ui service unit not installed."
            fi
        else
            if [ -f "${xui_service}/x-ui.service" ]; then
                systemctl stop x-ui > /dev/null 2>&1
                systemctl disable x-ui > /dev/null 2>&1
                echo -e "${green}Removing old systemd unit version...${plain}"
                rm ${xui_service}/x-ui.service -f > /dev/null 2>&1
                systemctl daemon-reload > /dev/null 2>&1
            else
                rm x-ui-linux-$(arch).tar.gz -f > /dev/null 2>&1
                _fail "ERROR: x-ui systemd unit not installed."
            fi
        fi
        echo -e "${green}Removing old x-ui version...${plain}"
        rm ${xui_folder} -f > /dev/null 2>&1
        rm ${xui_folder}/x-ui.service -f > /dev/null 2>&1
        rm ${xui_folder}/x-ui.service.debian -f > /dev/null 2>&1
        rm ${xui_folder}/x-ui.service.arch -f > /dev/null 2>&1
        rm ${xui_folder}/x-ui.service.rhel -f > /dev/null 2>&1
        rm ${xui_folder}/x-ui -f > /dev/null 2>&1
        rm ${xui_folder}/x-ui.sh -f > /dev/null 2>&1
        echo -e "${green}Removing old xray version...${plain}"
        rm ${xui_folder}/bin/xray-linux-amd64 -f > /dev/null 2>&1
        echo -e "${green}Removing old README and LICENSE file...${plain}"
        rm ${xui_folder}/bin/README.md -f > /dev/null 2>&1
        rm ${xui_folder}/bin/LICENSE -f > /dev/null 2>&1
    else
        rm x-ui-linux-$(arch).tar.gz -f > /dev/null 2>&1
        _fail "ERROR: x-ui not installed."
    fi

    echo -e "${green}Installing new x-ui version...${plain}"
    tar zxvf x-ui-linux-$(arch).tar.gz > /dev/null 2>&1
    rm x-ui-linux-$(arch).tar.gz -f > /dev/null 2>&1
    cd x-ui > /dev/null 2>&1
    chmod +x x-ui > /dev/null 2>&1

    # Check the system's architecture and rename the file accordingly
    if [[ $(arch) == "armv5" || $(arch) == "armv6" || $(arch) == "armv7" ]]; then
        mv bin/xray-linux-$(arch) bin/xray-linux-arm > /dev/null 2>&1
        chmod +x bin/xray-linux-arm > /dev/null 2>&1
    fi

    chmod +x x-ui bin/xray-linux-$(arch) > /dev/null 2>&1

    echo -e "${green}Downloading and installing x-ui.sh script...${plain}"
    ${curl_bin} -fLRo /usr/bin/x-ui https://raw.githubusercontent.com/sharif102007/4x-ui/main/x-ui.sh > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        echo -e "${yellow}Trying to fetch x-ui with IPv4...${plain}"
        ${curl_bin} -4fLRo /usr/bin/x-ui https://raw.githubusercontent.com/sharif102007/4x-ui/main/x-ui.sh > /dev/null 2>&1
        if [[ $? -ne 0 ]]; then
            _fail "ERROR: Failed to download x-ui.sh script, please be sure that your server can access GitHub"
        fi
    fi

    chmod +x ${xui_folder}/x-ui.sh > /dev/null 2>&1
    chmod +x /usr/bin/x-ui > /dev/null 2>&1
    mkdir -p /var/log/x-ui > /dev/null 2>&1

    echo -e "${green}Changing owner...${plain}"
    chown -R root:root ${xui_folder} > /dev/null 2>&1

    if [ -f "${xui_folder}/bin/config.json" ]; then
        echo -e "${green}Changing on config file permissions...${plain}"
        chmod 640 ${xui_folder}/bin/config.json > /dev/null 2>&1
    fi

    if [[ $release == "alpine" ]]; then
        echo -e "${green}Downloading and installing startup unit x-ui.rc...${plain}"
        ${curl_bin} -fLRo /etc/init.d/x-ui https://raw.githubusercontent.com/sharif102007/4x-ui/main/x-ui.rc > /dev/null 2>&1
        if [[ $? -ne 0 ]]; then
            ${curl_bin} -4fLRo /etc/init.d/x-ui https://raw.githubusercontent.com/sharif102007/4x-ui/main/x-ui.rc > /dev/null 2>&1
            if [[ $? -ne 0 ]]; then
                _fail "ERROR: Failed to download startup unit x-ui.rc, please be sure that your server can access GitHub"
            fi
        fi
        chmod +x /etc/init.d/x-ui > /dev/null 2>&1
        chown root:root /etc/init.d/x-ui > /dev/null 2>&1
        rc-update add x-ui > /dev/null 2>&1
    else
        if [ -f "x-ui.service" ]; then
            echo -e "${green}Installing systemd unit...${plain}"
            cp -f x-ui.service ${xui_service}/ > /dev/null 2>&1
            if [[ $? -ne 0 ]]; then
                echo -e "${red}Failed to copy x-ui.service${plain}"
                exit 1
            fi
        else
            service_installed=false
            case "${release}" in
                ubuntu | debian | armbian)
                    if [ -f "x-ui.service.debian" ]; then
                        echo -e "${green}Installing debian-like systemd unit...${plain}"
                        cp -f x-ui.service.debian ${xui_service}/x-ui.service > /dev/null 2>&1
                        if [[ $? -eq 0 ]]; then
                            service_installed=true
                        fi
                    fi
                    ;;
                arch | manjaro | parch)
                    if [ -f "x-ui.service.arch" ]; then
                        echo -e "${green}Installing arch-like systemd unit...${plain}"
                        cp -f x-ui.service.arch ${xui_service}/x-ui.service > /dev/null 2>&1
                        if [[ $? -eq 0 ]]; then
                            service_installed=true
                        fi
                    fi
                    ;;
                *)
                    if [ -f "x-ui.service.rhel" ]; then
                        echo -e "${green}Installing rhel-like systemd unit...${plain}"
                        cp -f x-ui.service.rhel ${xui_service}/x-ui.service > /dev/null 2>&1
                        if [[ $? -eq 0 ]]; then
                            service_installed=true
                        fi
                    fi
                    ;;
            esac

            # If service file not found in tar.gz, download from GitHub
            if [ "$service_installed" = false ]; then
                echo -e "${yellow}Service files not found in tar.gz, downloading from GitHub...${plain}"
                case "${release}" in
                    ubuntu | debian | armbian)
                        ${curl_bin} -4fLRo ${xui_service}/x-ui.service https://raw.githubusercontent.com/sharif102007/4x-ui/main/x-ui.service.debian > /dev/null 2>&1
                        ;;
                    arch | manjaro | parch)
                        ${curl_bin} -4fLRo ${xui_service}/x-ui.service https://raw.githubusercontent.com/sharif102007/4x-ui/main/x-ui.service.arch > /dev/null 2>&1
                        ;;
                    *)
                        ${curl_bin} -4fLRo ${xui_service}/x-ui.service https://raw.githubusercontent.com/sharif102007/4x-ui/main/x-ui.service.rhel > /dev/null 2>&1
                        ;;
                esac

                if [[ $? -ne 0 ]]; then
                    echo -e "${red}Failed to install x-ui.service from GitHub${plain}"
                    exit 1
                fi
            fi
        fi
        chown root:root ${xui_service}/x-ui.service > /dev/null 2>&1
        chmod 644 ${xui_service}/x-ui.service > /dev/null 2>&1
        systemctl daemon-reload > /dev/null 2>&1
        systemctl enable x-ui > /dev/null 2>&1
    fi

    config_after_update
    repair_inbound_certificates
    ensure_panel_running

    echo -e "${green}x-ui ${tag_version}${plain} updating finished, it is running now..."
    echo -e ""
    echo -e "┌───────────────────────────────────────────────────────┐
│  ${blue}x-ui control menu usages (subcommands):${plain}              │
│                                                       │
│  ${blue}x-ui${plain}              - Admin Management Script          │
│  ${blue}x-ui start${plain}        - Start                            │
│  ${blue}x-ui stop${plain}         - Stop                             │
│  ${blue}x-ui restart${plain}      - Restart                          │
│  ${blue}x-ui status${plain}       - Current Status                   │
│  ${blue}x-ui settings${plain}     - Current Settings                 │
│  ${blue}x-ui enable${plain}       - Enable Autostart on OS Startup   │
│  ${blue}x-ui disable${plain}      - Disable Autostart on OS Startup  │
│  ${blue}x-ui log${plain}          - Check logs                       │
│  ${blue}x-ui banlog${plain}       - Check Fail2ban ban logs          │
│  ${blue}x-ui update${plain}       - Update                           │
│  ${blue}x-ui legacy${plain}       - Legacy version                   │
│  ${blue}x-ui install${plain}      - Install                          │
│  ${blue}x-ui uninstall${plain}    - Uninstall                        │
└───────────────────────────────────────────────────────┘"
}

echo -e "${green}Running...${plain}"
install_base
update_x-ui $1
