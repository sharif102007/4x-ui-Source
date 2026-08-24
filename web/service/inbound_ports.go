package service

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sharif102007/4x-ui/v2/database"
	"github.com/sharif102007/4x-ui/v2/database/model"
	"github.com/sharif102007/4x-ui/v2/logger"
)

// ---------------------------------------------------------------------------
// Cross-service port conflicts
// ---------------------------------------------------------------------------
//
// checkPortExist only ever looked at the inbounds table, so an Xray inbound
// could be saved on a port already owned by an SSH Manager inbound, the panel
// itself or the subscription server. The row saved fine and then Xray failed to
// bind at runtime, which surfaces as "the panel broke" rather than "that port is
// taken". The SSH Manager already refuses the mirror image of this
// (collectReservedPorts), so this closes the other direction.
//
// Deliberately advisory-by-omission: if any lookup fails (the ssh_inbounds
// table does not exist yet on a fresh upgrade, settings unreadable, ...) the
// port is treated as free rather than blocking the save. A false rejection is
// worse than the runtime bind error this is trying to prevent.

// externalPortOwner returns a human-readable owner if port is claimed by
// something outside the Xray inbounds table, or "" if it is free.
func (s *InboundService) externalPortOwner(port int) string {
	if port <= 0 {
		return ""
	}
	db := database.GetDB()
	if db == nil {
		return ""
	}

	// SSH Manager inbounds. Guarded with HasTable because this table is
	// created by initModels and may legitimately be absent mid-migration.
	if db.Migrator().HasTable(&model.SshInbound{}) {
		var sshInbounds []model.SshInbound
		if err := db.Find(&sshInbounds).Error; err == nil {
			for _, in := range sshInbounds {
				switch port {
				case in.ListenPort:
					return fmt.Sprintf("SSH inbound %q (listen port)", in.Name)
				case in.BackendSshPort:
					return fmt.Sprintf("SSH inbound %q (backend OpenSSH port)", in.Name)
				case in.GatewayPort:
					return fmt.Sprintf("SSH inbound %q (payload gateway port)", in.Name)
				case in.UdpRelayPort:
					return fmt.Sprintf("SSH inbound %q (UDP relay port)", in.Name)
				}
			}
		}
	}

	settingService := SettingService{}
	if p, err := settingService.GetPort(); err == nil && p == port {
		return "the 4x-ui panel"
	}
	if p, err := settingService.GetSubPort(); err == nil && p == port {
		return "the subscription server"
	}
	return ""
}

// checkExternalPortConflict is the error-returning wrapper used by
// AddInbound/UpdateInbound.
func (s *InboundService) checkExternalPortConflict(port int) error {
	if owner := s.externalPortOwner(port); owner != "" {
		return fmt.Errorf("port %d is already used by %s", port, owner)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Firewall
// ---------------------------------------------------------------------------

// inboundFirewallProtocols reports which L4 protocols an inbound actually needs
// open. Everything needs TCP except the purely UDP-based protocols; QUIC and
// mKCP transports add UDP on top of whatever the protocol itself uses.
//
// Erring towards opening both is safe: an unused allow rule costs nothing,
// whereas a missing UDP rule makes a Hysteria inbound look completely dead.
func inboundFirewallProtocols(in *model.Inbound) []string {
	if in == nil {
		return nil
	}
	udp := false
	tcp := true

	switch {
	case model.IsHysteria(in.Protocol):
		// Hysteria/Hysteria2 are QUIC, i.e. UDP only.
		udp, tcp = true, false
	case in.Protocol == model.WireGuard:
		udp, tcp = true, false
	}

	// Transport-level UDP: mKCP and QUIC run over UDP regardless of protocol.
	if in.StreamSettings != "" {
		var stream struct {
			Network string `json:"network"`
		}
		if err := json.Unmarshal([]byte(in.StreamSettings), &stream); err == nil {
			switch strings.ToLower(stream.Network) {
			case "kcp", "mkcp", "quic":
				udp = true
			}
		}
	}

	protos := make([]string, 0, 2)
	if tcp {
		protos = append(protos, "tcp")
	}
	if udp {
		protos = append(protos, "udp")
	}
	return protos
}

// openInboundFirewall opens an inbound's port on the active firewall. Best
// effort and never fatal: no firewall running means there is nothing to do.
func openInboundFirewall(in *model.Inbound) {
	if in == nil || !in.Enable || in.Port <= 0 {
		return
	}
	// A listen address bound to loopback is not reachable from outside and
	// must not get a firewall hole.
	switch strings.TrimSpace(in.Listen) {
	case "127.0.0.1", "::1", "localhost":
		return
	}
	protos := inboundFirewallProtocols(in)
	if len(protos) == 0 {
		return
	}
	AllowInboundPort(in.Port, protos...)
	logger.Debugf("inbound %s: requested firewall open for %d/%s", in.Tag, in.Port, strings.Join(protos, ","))
}
