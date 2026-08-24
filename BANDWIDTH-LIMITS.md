# Traffic, speed, and network behavior

4x-ui manages per-user limits for both Xray clients and SSH Manager users on
Linux. The installer provides nftables, iproute2, and stunnel; the panel owns
only the `inet fourxui_xray` and `inet fourxui_ssh` nftables tables.

## SSH Manager

- Linux UID rules mark each managed user's connections.
- One nftables table read collects every user's upload/download counters every
  fifteen seconds; it does not start a process per user.
- Total-flow exhaustion or account expiry locks the Linux account.
- Upload and download rates can be configured independently.
- The generated OpenSSH drop-in keeps modern algorithms first and includes
  legacy fallbacks needed by older Android clients such as HTTP Custom. Every
  change is checked with `sshd -t` and rolled back if invalid.

After upgrading an older installation, save/apply SSH Manager once to regenerate
its managed OpenSSH drop-in.

## Xray clients

For supported multi-user protocols, a client with an email can have separate
upload and download limits. 4x-ui creates a marked freedom outbound for that
client and installs the matching nftables/tc policy. The normal Xray statistics
database remains the source of truth for quota, reset, expiry, and automatic
disable operations.

Routing order is deliberate:

1. Xray API infrastructure rule
2. Blackhole/block rules
3. Per-client speed rules
4. Other custom rules

Without an active speed limit, the existing routing order is preserved (apart
from repairing/hoisting the required API rule). A limited client uses its marked
outbound, so it cannot simultaneously follow a custom rule that sends the same
traffic through another proxy outbound.

## Enforcement

nftables supplies counters and a fallback policer. When the host supports HTB,
IFB, and `act_connmark`, `4xui-shaper.sh` is reconciled automatically whenever
the configured limits change:

- Upload uses HTB on WAN egress only when at least one upload limit exists.
- Download restores the connection mark on WAN ingress but redirects only marks
  with an actual download limit to `ifb-4xui`; unlimited/game traffic stays on
  the native ingress path.
- Each limited class uses `fq_codel`.
- Unclassified upload traffic uses a full-speed default class when upload HTB is
  active.

If queue shaping is unavailable, the panel logs the reason and keeps the
nftables policer active. A policer drops excess packets, so TCP can measure
below its configured cap and UDP/QUIC can experience packet loss.

## SSH latency and UDP relay

Generated stunnel services set `TCP_NODELAY` on both local and remote sockets,
and the payload gateway explicitly disables Nagle on both TCP hops. SSH counter
polling runs every 15 seconds to avoid unnecessary periodic load on small VPS
instances.

When an enabled SSH inbound has a UDP Relay Port, 4x-ui automatically ensures
`badvpn-udpgw` is installed and manages one listener per unique port. On systemd
hosts the persistent unit is `xui-udpgw@<port>.service`; multiple inbounds may
share the default port 7300. The listener is loopback-only and clients use
`127.0.0.1:<port>` as their UDPGW endpoint through the SSH tunnel.

If automatic installation or listener startup fails, inbound reconciliation
fails and the panel operation rolls back instead of reporting a false active
state. `x-ui diag` reports the TCP UDPGW listener and its systemd unit.

## Diagnostics

```bash
x-ui diag
x-ui diag counters
x-ui shaper check
x-ui shaper status
```

Verify throughput from another host with `iperf3`; a UI switch alone does not
prove that kernel marking and shaping are active.

## Optional network tuning

```bash
x-ui netopt apply
x-ui netopt status
x-ui netopt rollback
```

Only sysctl keys exposed by the running kernel are written. Buffer ceilings
scale with RAM, BBR is selected only when available, and the original values
are saved in `/etc/x-ui/network-sysctl-backup.conf`. There is no
`net.ipv4.tcp_nodelay` sysctl: Go already enables TCP_NODELAY for its TCP
sockets, while Xray manages its own sockets.

The panel sets a soft Go memory limit to 75% of the cgroup or host memory limit.
Set `XUI_MEMORY_LIMIT=<bytes>` to override it, or `XUI_MEMORY_LIMIT=0` to retain
the Go runtime default.

## Runtime requirements

- Root privileges, or equivalent nftables/tc capabilities
- Docker host networking with `NET_ADMIN` and `NET_RAW`
- A kernel with nftables; HTB/IFB/act_connmark are needed for queue shaping
## SSH inbound save and UDPGW setup

- Normal SSH inbound saves use no-op detection: unchanged OpenSSH and stunnel
  configs are not restarted. A previously managed, healthy UDPGW listener is
  also reused without repeated `systemctl enable/start` or the startup wait.
- The first UDP Relay enable remains synchronous so the panel never reports a
  working relay before the VPS listener exists. On Debian/Ubuntu, 4x-ui repairs
  interrupted `dpkg` state automatically, runs `apt-get -f install`, waits for
  legitimate apt/dpkg locks, then installs or builds `badvpn-udpgw`. Lock files
  are never force-deleted.

