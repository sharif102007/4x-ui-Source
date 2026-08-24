#!/usr/bin/env bash
#
# 4x-ui network optimization
#
# Applies only sysctl keys that the running kernel actually exposes, records the
# previous value of every key it touches, and can restore them exactly.
#
#   network-optimize.sh apply      apply tuning (idempotent)
#   network-optimize.sh rollback   restore the values saved by the last apply
#   network-optimize.sh status     show current values of every managed key
#
# Notes:
#  - TCP_NODELAY is a per-socket option (setsockopt), not a sysctl. It is set by
#    the panel/Xray on their own sockets; there is nothing to tune here. It is
#    listed in status output for clarity only.
#  - Nothing is applied unless `sysctl -n <key>` succeeds, so an unsupported
#    parameter is skipped instead of producing a boot-time error.

set -uo pipefail

CONF_FILE="/etc/sysctl.d/99-4xui-network.conf"
BACKUP_DIR="/etc/x-ui"
BACKUP_FILE="${BACKUP_DIR}/network-sysctl-backup.conf"
MARKER="# managed by 4x-ui network-optimize.sh"

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

info() { echo -e "${green}[ok]${plain}   $*"; }
warn() { echo -e "${yellow}[skip]${plain} $*"; }
err() { echo -e "${red}[err]${plain}  $*" >&2; }

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        err "must run as root"
        exit 1
    fi
}

# key_supported <key> - true when the running kernel exposes the key.
key_supported() {
    sysctl -n "$1" >/dev/null 2>&1
}

# total RAM in MB, used to size socket buffers. A 512MB VPS must not be told to
# reserve 128MB per direction.
total_ram_mb() {
    local kb
    kb=$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null)
    if [[ -z "${kb}" ]]; then
        echo 1024
        return
    fi
    echo $((kb / 1024))
}

cpu_count() {
    local n
    n=$(nproc 2>/dev/null || echo 1)
    [[ "${n}" -ge 1 ]] 2>/dev/null || n=1
    echo "${n}"
}

# Buffer ceiling scaled to available RAM. Upper bound is the 128MB the project
# asked for; smaller boxes get proportionally less so the kernel does not end up
# able to pin most of RAM in socket buffers.
buffer_max_bytes() {
    local ram
    ram=$(total_ram_mb)
    if [[ "${ram}" -lt 1024 ]]; then
        echo $((16 * 1024 * 1024))
    elif [[ "${ram}" -lt 2048 ]]; then
        echo $((32 * 1024 * 1024))
    elif [[ "${ram}" -lt 4096 ]]; then
        echo $((64 * 1024 * 1024))
    else
        echo $((128 * 1024 * 1024))
    fi
}

# bbr_available - true when BBR is usable, loading the module if needed.
bbr_available() {
    if ! key_supported net.ipv4.tcp_available_congestion_control; then
        return 1
    fi
    if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
        return 0
    fi
    if command -v modprobe >/dev/null 2>&1; then
        modprobe tcp_bbr >/dev/null 2>&1 || true
    fi
    sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr
}

# tw_reuse_safe - tcp_tw_reuse relies on TCP timestamps to tell old duplicate
# segments from new ones. Without timestamps it is not safe to enable.
tw_reuse_safe() {
    key_supported net.ipv4.tcp_timestamps || return 1
    [[ "$(sysctl -n net.ipv4.tcp_timestamps 2>/dev/null)" == "1" ]]
}

# Build the desired key=value set for this host.
build_settings() {
    local buf_max buf_default cpus somaxconn backlog
    buf_max=$(buffer_max_bytes)
    # Defaults stay modest: rmem_default applies to every socket on the box,
    # while rmem_max is only a ceiling that autotuning may grow into.
    buf_default=$((1024 * 1024))
    cpus=$(cpu_count)

    somaxconn=4096
    backlog=$((4096 * cpus))
    if [[ "${backlog}" -gt 65536 ]]; then
        backlog=65536
    fi

    cat <<EOF
net.core.rmem_max=${buf_max}
net.core.wmem_max=${buf_max}
net.core.rmem_default=${buf_default}
net.core.wmem_default=${buf_default}
net.core.somaxconn=${somaxconn}
net.core.netdev_max_backlog=${backlog}
net.ipv4.tcp_rmem=4096 131072 ${buf_max}
net.ipv4.tcp_wmem=4096 131072 ${buf_max}
net.ipv4.udp_rmem_min=16384
net.ipv4.udp_wmem_min=16384
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_max_syn_backlog=${backlog}
net.ipv4.tcp_keepalive_time=120
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.ip_local_port_range=10240 65000
net.ipv4.tcp_notsent_lowat=131072
EOF

    if tw_reuse_safe; then
        echo "net.ipv4.tcp_tw_reuse=1"
    fi

    if bbr_available; then
        echo "net.ipv4.tcp_congestion_control=bbr"
        # fq pairs with BBR; fq_codel is the fallback if fq is absent.
        if key_supported net.core.default_qdisc; then
            if command -v tc >/dev/null 2>&1 && tc qdisc add dev lo root fq 2>/dev/null; then
                tc qdisc del dev lo root 2>/dev/null || true
                echo "net.core.default_qdisc=fq"
            else
                echo "net.core.default_qdisc=fq_codel"
            fi
        fi
    fi

    # UDP conntrack timeouts only exist once nf_conntrack is loaded. Long-lived
    # QUIC/Hysteria flows are dropped from the table too early at the default.
    if key_supported net.netfilter.nf_conntrack_udp_timeout; then
        echo "net.netfilter.nf_conntrack_udp_timeout=60"
    fi
    if key_supported net.netfilter.nf_conntrack_udp_timeout_stream; then
        echo "net.netfilter.nf_conntrack_udp_timeout_stream=180"
    fi
    if key_supported net.netfilter.nf_conntrack_max; then
        local ram ct_max
        ram=$(total_ram_mb)
        ct_max=$((ram * 256))
        if [[ "${ct_max}" -lt 65536 ]]; then
            ct_max=65536
        fi
        if [[ "${ct_max}" -gt 1048576 ]]; then
            ct_max=1048576
        fi
        echo "net.netfilter.nf_conntrack_max=${ct_max}"
    fi
}

do_apply() {
    require_root
    mkdir -p "${BACKUP_DIR}"

    local settings key value current
    settings=$(build_settings)

    # Back up current values once per apply, overwriting the previous backup only
    # after a successful full read, so a partial write cannot lose the original.
    local tmp_backup
    tmp_backup=$(mktemp) || {
        err "cannot create temp file"
        exit 1
    }
    {
        echo "${MARKER}"
        echo "# saved $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    } >"${tmp_backup}"

    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        key="${line%%=*}"
        if ! key_supported "${key}"; then
            continue
        fi
        current=$(sysctl -n "${key}" 2>/dev/null)
        # tabs/multiple spaces in vector values (tcp_rmem) collapse to one space
        current=$(echo "${current}" | tr -s '[:space:]' ' ' | sed 's/ *$//')
        echo "${key}=${current}" >>"${tmp_backup}"
    done <<<"${settings}"

    if [[ ! -f "${BACKUP_FILE}" ]]; then
        mv "${tmp_backup}" "${BACKUP_FILE}"
        chmod 600 "${BACKUP_FILE}"
        info "saved original sysctl values to ${BACKUP_FILE}"
    else
        rm -f "${tmp_backup}"
        info "keeping existing backup ${BACKUP_FILE} (originals from first apply)"
    fi

    # Write the config file, skipping unsupported keys.
    local tmp_conf applied=0 skipped=0
    tmp_conf=$(mktemp) || {
        err "cannot create temp file"
        exit 1
    }
    {
        echo "${MARKER}"
        echo "# regenerate with: x-ui netopt apply"
        echo "# revert with:     x-ui netopt rollback"
    } >"${tmp_conf}"

    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        key="${line%%=*}"
        value="${line#*=}"
        if ! key_supported "${key}"; then
            warn "${key} not supported by this kernel"
            skipped=$((skipped + 1))
            continue
        fi
        echo "${key} = ${value}" >>"${tmp_conf}"
        applied=$((applied + 1))
    done <<<"${settings}"

    mv "${tmp_conf}" "${CONF_FILE}"
    chmod 644 "${CONF_FILE}"

    if sysctl --system >/dev/null 2>&1; then
        info "applied ${applied} sysctl keys (${skipped} skipped as unsupported)"
    else
        err "sysctl --system reported an error; check: sysctl --system"
        return 1
    fi

    echo
    echo "TCP_NODELAY is a per-socket option and is set by the panel and Xray"
    echo "on their own sockets; it has no sysctl equivalent."
    return 0
}

do_rollback() {
    require_root
    if [[ ! -f "${BACKUP_FILE}" ]]; then
        err "no backup at ${BACKUP_FILE}; nothing to roll back"
        return 1
    fi

    rm -f "${CONF_FILE}"

    local key value restored=0
    while IFS= read -r line; do
        [[ -z "${line}" || "${line}" == \#* ]] && continue
        key="${line%%=*}"
        value="${line#*=}"
        if ! key_supported "${key}"; then
            continue
        fi
        # shellcheck disable=SC2086
        if sysctl -w "${key}"="${value}" >/dev/null 2>&1; then
            restored=$((restored + 1))
        else
            warn "could not restore ${key}"
        fi
    done <"${BACKUP_FILE}"

    sysctl --system >/dev/null 2>&1 || true
    info "restored ${restored} sysctl keys and removed ${CONF_FILE}"
    return 0
}

do_status() {
    local settings key
    settings=$(build_settings)
    echo "Managed sysctl keys (current running values):"
    echo
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        key="${line%%=*}"
        if key_supported "${key}"; then
            printf '  %-48s %s\n' "${key}" "$(sysctl -n "${key}" 2>/dev/null | tr -s '[:space:]' ' ')"
        else
            printf '  %-48s %s\n' "${key}" "(unsupported)"
        fi
    done <<<"${settings}"
    echo
    if [[ -f "${CONF_FILE}" ]]; then
        info "tuning file present: ${CONF_FILE}"
    else
        warn "tuning not applied (no ${CONF_FILE})"
    fi
    if [[ -f "${BACKUP_FILE}" ]]; then
        info "rollback data present: ${BACKUP_FILE}"
    else
        warn "no rollback data"
    fi
    echo
    echo "  TCP_NODELAY: per-socket option, no sysctl (informational)"
}

case "${1:-}" in
    apply) do_apply ;;
    rollback) do_rollback ;;
    status) do_status ;;
    *)
        echo "usage: $0 {apply|rollback|status}"
        exit 1
        ;;
esac
