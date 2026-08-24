#!/usr/bin/env bash
#
# 4x-ui limits diagnostics
#
# Dumps everything needed to answer "is the speed/traffic limit actually being
# enforced?" without guessing: the nftables tables the panel owns, their byte
# counters, any tc shaping state, and the relevant kernel modules.
#
#   limits-diag.sh            full report
#   limits-diag.sh counters   byte counters only (safe to poll)

set -uo pipefail

SSH_TABLE="fourxui_ssh"
XRAY_TABLE="fourxui_xray"

green='\033[0;32m'
yellow='\033[0;33m'
red='\033[0;31m'
plain='\033[0m'

hdr() { echo -e "\n${green}=== $* ===${plain}"; }
warn() { echo -e "${yellow}$*${plain}"; }
bad() { echo -e "${red}$*${plain}"; }

have() { command -v "$1" >/dev/null 2>&1; }

show_table() {
    local table="$1"
    if ! have nft; then
        bad "nft not installed - no nftables limit can be enforced"
        return
    fi
    if nft list table inet "${table}" >/dev/null 2>&1; then
        nft list table inet "${table}"
    else
        warn "table inet ${table} does not exist (no active limits from this subsystem)"
    fi
}

show_counters() {
    local table="$1"
    if ! have nft; then
        return
    fi
    if ! nft list table inet "${table}" >/dev/null 2>&1; then
        warn "table inet ${table}: absent"
        return
    fi
    # counter lines look like:  counter xray_2a1b3c_up { packets 12 bytes 3456 }
    nft -a list table inet "${table}" 2>/dev/null |
        awk '/counter [a-zA-Z0-9_]+ \{/ {
                name=$2
                for (i=1;i<=NF;i++) {
                    if ($i=="packets") pkts=$(i+1)
                    if ($i=="bytes") byts=$(i+1)
                }
                printf "  %-28s packets=%-12s bytes=%s\n", name, pkts, byts
            }'
}

show_tc() {
    if ! have tc; then
        warn "tc not installed (iproute2 missing) - no queue-based shaping possible"
        return
    fi
    local dev
    for dev in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1); do
        case "${dev}" in
            lo) continue ;;
        esac
        local qdisc
        qdisc=$(tc qdisc show dev "${dev}" 2>/dev/null)
        if [[ -n "${qdisc}" ]]; then
            echo "--- ${dev} ---"
            echo "${qdisc}"
            tc -s class show dev "${dev}" 2>/dev/null | head -40
            tc filter show dev "${dev}" 2>/dev/null | head -20
        fi
    done
}

show_modules() {
    local m
    for m in nf_tables nf_conntrack sch_htb sch_ingress act_mirred act_connmark cls_fw ifb tcp_bbr; do
        if [[ -d "/sys/module/${m}" ]]; then
            echo "  loaded      ${m}"
        elif have modinfo && modinfo "${m}" >/dev/null 2>&1; then
            echo "  available   ${m} (not loaded)"
        else
            echo "  MISSING     ${m}"
        fi
    done
}

do_counters() {
    hdr "SSH byte counters (${SSH_TABLE})"
    show_counters "${SSH_TABLE}"
    hdr "Xray byte counters (${XRAY_TABLE})"
    show_counters "${XRAY_TABLE}"
}

do_full() {
    hdr "tooling"
    for c in nft tc ip ss iperf3 sysctl; do
        if have "${c}"; then
            echo "  present     ${c}"
        else
            echo "  MISSING     ${c}"
        fi
    done

    hdr "kernel modules"
    show_modules

    hdr "nftables: ${SSH_TABLE}"
    show_table "${SSH_TABLE}"

    hdr "nftables: ${XRAY_TABLE}"
    show_table "${XRAY_TABLE}"

    do_counters

    hdr "tc shaping state"
    show_tc

    hdr "socket summary"
    if have ss; then
        ss -s 2>/dev/null
        echo
        echo "listening sockets:"
        ss -tulnp 2>/dev/null | head -30
    else
        warn "ss not available"
    fi

    hdr "congestion control"
    sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | sed 's/^/  active:    /'
    sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | sed 's/^/  available: /'
    sysctl -n net.core.default_qdisc 2>/dev/null | sed 's/^/  qdisc:     /'

    hdr "how to interpret this"
    cat <<'EOF'
  * A table listed as "absent" means that subsystem is enforcing nothing.
  * Byte counters that stay at 0 while a client is transferring data mean the
    packet mark is not reaching the chain: the rule exists but never matches.
  * Counters rising while throughput is unlimited means marking works but the
    rate rule is not effective.
  * Verify real throughput separately, e.g.:
      iperf3 -s                      (on a second host)
      iperf3 -c <host> -t 30         TCP
      iperf3 -c <host> -u -b 100M    UDP
EOF
}


# ---------------------------------------------------------------------------
# UDP health
# ---------------------------------------------------------------------------
#
# There is no way to measure real UDP throughput or loss from one host alone,
# so this does not pretend to. Instead it reports the things that actually
# explain UDP loss on a VPS - kernel drop counters, socket buffer ceilings,
# conntrack pressure and the udpgw relay state - and runs a real throughput
# test only when iperf3 and a peer are supplied.
#
#   limits-diag.sh udp                    counters and settings only
#   limits-diag.sh udp <host> [seconds]   also run an iperf3 UDP test to <host>
show_udp_counters() {
    hdr "UDP kernel counters (/proc/net/snmp)"
    if [[ -r /proc/net/snmp ]]; then
        awk '/^Udp:/ { if (h == "") { h = $0; split($0, k, " ") } else { split($0, v, " ");
             for (i = 2; i <= length(k); i++) printf "  %-16s %s\n", k[i], v[i] } }' /proc/net/snmp
        echo
        echo "  RcvbufErrors / InErrors above zero and rising = real UDP loss on this host."
        echo "  NoPorts rising = traffic arriving for a port nothing is listening on."
    else
        warn "  /proc/net/snmp unreadable"
    fi

    hdr "UDP socket buffers"
    for k in net.core.rmem_max net.core.wmem_max net.ipv4.udp_rmem_min net.ipv4.udp_wmem_min; do
        printf "  %-32s %s\n" "${k}" "$(sysctl -n "${k}" 2>/dev/null || echo 'n/a')"
    done

    hdr "UDP conntrack"
    for k in net.netfilter.nf_conntrack_udp_timeout net.netfilter.nf_conntrack_udp_timeout_stream \
             net.netfilter.nf_conntrack_max net.netfilter.nf_conntrack_count; do
        printf "  %-48s %s\n" "${k}" "$(sysctl -n "${k}" 2>/dev/null || echo 'n/a')"
    done
    local cur max
    cur=$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null || echo "")
    max=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo "")
    if [[ -n "${cur}" && -n "${max}" && "${max}" -gt 0 ]]; then
        if (( cur * 100 / max > 80 )); then
            bad "  conntrack table is over 80% full - new UDP flows will be dropped"
        fi
    fi

    hdr "SSH UDP relay (badvpn-udpgw)"
    if have badvpn-udpgw; then
        echo "  binary: $(command -v badvpn-udpgw)"
    else
        warn "  badvpn-udpgw not installed - SSH tunnels have no UDP support"
    fi
    if have ss; then
        local listeners
        listeners=$(ss -ltnp 2>/dev/null | grep -i udpgw || true)
        if [[ -n "${listeners}" ]]; then
            echo "${listeners}" | sed 's/^/  /'
        else
            warn "  no TCP udpgw listener found"
        fi
    fi
    if have ps; then
        ps -eo args 2>/dev/null | grep '[b]advpn-udpgw' | sed 's/^/  args: /' || true
    fi
    if have systemctl; then
        systemctl --no-pager --plain --type=service --all 2>/dev/null | \
            grep 'xui-udpgw@' | sed 's/^/  service: /' || true
    fi
}

do_udp() {
    local peer="${1:-}"
    local secs="${2:-10}"

    show_udp_counters

    if [[ -z "${peer}" ]]; then
        hdr "Throughput test"
        echo "  Skipped. A real UDP throughput/loss measurement needs a second host."
        echo "  On a peer:  iperf3 -s"
        echo "  Then here:  limits-diag.sh udp <peer-ip> [seconds]"
        return 0
    fi

    if ! have iperf3; then
        hdr "Throughput test"
        bad "  iperf3 not installed (apt-get install -y iperf3)"
        return 1
    fi

    hdr "UDP throughput and loss to ${peer} (${secs}s)"
    echo "  Uplink:"
    iperf3 -c "${peer}" -u -b 0 -t "${secs}" 2>&1 | sed 's/^/    /'
    echo
    echo "  Downlink:"
    iperf3 -c "${peer}" -u -b 0 -t "${secs}" -R 2>&1 | sed 's/^/    /'
    echo
    echo "  Read the Lost/Total Datagrams column. Loss under ~1% on a clean link"
    echo "  is normal; anything higher with rising RcvbufErrors above points at"
    echo "  socket buffers rather than the network."
}

case "${1:-full}" in
    counters) do_counters ;;
    full) do_full ;;
    udp) do_udp "${2:-}" "${3:-10}" ;;
    *)
        echo "usage: $0 {full|counters|udp [peer-host] [seconds]}"
        exit 1
        ;;
esac
