package service

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/sharif102007/4x-ui/v2/database"
	"github.com/sharif102007/4x-ui/v2/database/model"
	"github.com/sharif102007/4x-ui/v2/logger"
)

// SshManagerService is the orchestration layer for the SSH Manager feature. It
// owns the database rows and reconciles the live host (OpenSSH drop-in,
// stunnel, payload gateways, firewall) to match the enabled inbounds.
type SshManagerService struct {
	settingService SettingService
}

var sshSys sshSystem

// Runtime state for the in-process payload gateways. The service structs in
// this project are zero-value/stateless and created ad hoc, so the running
// gateways live in package-level state guarded by a mutex.
var (
	sshRuntimeMu sync.Mutex
	sshGateways  = map[int]*payloadGateway{} // key: inbound ID
)

// gatewaySpec holds the config needed to start/compare a payload gateway.
type gatewaySpec struct {
	bindIP  string
	listen  int
	backend int
}

// ---------------------------------------------------------------------------
// Password encryption (AES-256-GCM, key derived from the panel secret)
// ---------------------------------------------------------------------------

func (s *SshManagerService) secretKey() ([]byte, error) {
	secret, err := s.settingService.GetSecret()
	if err != nil {
		return nil, err
	}
	return deriveKey(string(secret)), nil
}

func (s *SshManagerService) encryptPassword(plain string) (string, error) {
	key, err := s.secretKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

func (s *SshManagerService) decryptPassword(enc string) (string, error) {
	if enc == "" {
		return "", nil
	}
	key, err := s.secretKey()
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return "", errors.New("ciphertext too short")
	}
	plain, err := gcm.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// ---------------------------------------------------------------------------
// Inbound validation & port-conflict checking
// ---------------------------------------------------------------------------

func validMode(m string) bool {
	switch m {
	case model.SshModeNormal, model.SshModeTlsSni, model.SshModeTlsPayload, model.SshModePayloadOnly:
		return true
	}
	return false
}

func (s *SshManagerService) validateInbound(in *model.SshInbound) error {
	if strings.TrimSpace(in.Name) == "" {
		return errors.New("name is required")
	}
	if !validMode(in.Mode) {
		return errors.New("invalid mode")
	}
	if err := validPort(in.ListenPort); err != nil {
		return err
	}
	if in.UdpRelayPort > 0 {
		if err := validPort(in.UdpRelayPort); err != nil {
			return fmt.Errorf("UDP relay port: %v", err)
		}
		// badvpn-udpgw is a local TCP listener. It must not collide with this
		// inbound's public/backend/gateway listener. Multiple SSH inbounds may
		// intentionally share one UDPGW port and are deduplicated later.
		if in.UdpRelayPort == in.ListenPort || in.UdpRelayPort == in.BackendSshPort ||
			(in.GatewayPort > 0 && in.UdpRelayPort == in.GatewayPort) {
			return errors.New("UDP relay port must differ from this inbound's SSH ports")
		}
	}
	switch in.Mode {
	case model.SshModeNormal:
		// public port IS the backend port
		in.BackendSshPort = in.ListenPort
		in.GatewayPort = 0

	case model.SshModePayloadOnly:
		// plain TCP payload gateway — no TLS, no cert fields needed
		if err := validPort(in.BackendSshPort); err != nil {
			return fmt.Errorf("backend ssh port: %v", err)
		}
		if in.BackendSshPort == in.ListenPort {
			return errors.New("backend ssh port must differ from the public listen port")
		}
		in.GatewayPort = 0
		in.CertMode = ""
		in.CertFile = ""
		in.KeyFile = ""

	default: // ssh_tls_sni, ssh_tls_payload
		if err := validPort(in.BackendSshPort); err != nil {
			return fmt.Errorf("backend ssh port: %v", err)
		}
		if in.BackendSshPort == in.ListenPort {
			return errors.New("backend ssh port must differ from the public TLS port")
		}
		switch in.CertMode {
		case model.SshCertExisting:
			cf, err := cleanCertPath(in.CertFile)
			if err != nil {
				return fmt.Errorf("cert file: %v", err)
			}
			kf, err := cleanCertPath(in.KeyFile)
			if err != nil {
				return fmt.Errorf("key file: %v", err)
			}
			in.CertFile, in.KeyFile = cf, kf
		case model.SshCertSelfSigned, "":
			in.CertMode = model.SshCertSelfSigned
		default:
			return errors.New("invalid certificate mode")
		}
	}
	return nil
}

// collectReservedPorts returns every port already spoken for by other SSH
// inbounds, the panel itself and Xray inbounds, so a new/edited inbound cannot
// silently clash with anything (including 4x-ui/Xray TLS ports).
func (s *SshManagerService) collectReservedPorts(excludeInboundID int) map[int]string {
	reserved := map[int]string{}
	db := database.GetDB()

	var others []model.SshInbound
	db.Find(&others)
	for _, o := range others {
		if o.Id == excludeInboundID {
			continue
		}
		if o.ListenPort > 0 {
			reserved[o.ListenPort] = "another SSH inbound (" + o.Name + ")"
		}
		if o.BackendSshPort > 0 {
			reserved[o.BackendSshPort] = "another SSH inbound backend (" + o.Name + ")"
		}
		if o.GatewayPort > 0 {
			reserved[o.GatewayPort] = "another SSH inbound gateway (" + o.Name + ")"
		}
		if o.UdpRelayPort > 0 {
			// Public/backend/gateway listeners must not collide with another
			// UDPGW listener. checkInboundPorts has a deliberate exception when
			// the candidate itself is sharing this same UDPGW port.
			reserved[o.UdpRelayPort] = "another SSH UDP relay"
		}
	}

	// Xray inbounds
	var xinb []model.Inbound
	db.Model(&model.Inbound{}).Find(&xinb)
	for _, x := range xinb {
		if x.Port > 0 {
			reserved[x.Port] = "an Xray inbound"
		}
	}

	// Panel + subscription ports
	if p, err := s.settingService.GetPort(); err == nil && p > 0 {
		reserved[p] = "the 4x-ui panel"
	}
	if p, err := s.settingService.GetSubPort(); err == nil && p > 0 {
		reserved[p] = "the subscription server"
	}
	return reserved
}

// CheckPortConflict validates one candidate public port for the UI pre-check.
func (s *SshManagerService) CheckPortConflict(port, excludeInboundID int) error {
	if err := validPort(port); err != nil {
		return err
	}
	reserved := s.collectReservedPorts(excludeInboundID)
	if reason, clash := reserved[port]; clash {
		return fmt.Errorf("port %d is already used by %s", port, reason)
	}
	// Live probe (skip if it is the existing public port of the edited inbound).
	if excludeInboundID > 0 {
		if cur, err := s.GetInbound(excludeInboundID); err == nil && cur.ListenPort == port && cur.Enable {
			return nil
		}
	}
	if !sshSys.portFree(port) {
		return fmt.Errorf("port %d is currently in use by another process", port)
	}
	return nil
}

// checkInboundPorts validates all ports an inbound wants to occupy.
func (s *SshManagerService) checkInboundPorts(in *model.SshInbound) error {
	reserved := s.collectReservedPorts(in.Id)

	check := func(p int, label string, allowSharedUDP bool) error {
		if p <= 0 {
			return nil
		}
		if reason, clash := reserved[p]; clash {
			if allowSharedUDP && reason == "another SSH UDP relay" {
				return nil
			}
			return fmt.Errorf("%s port %d is already used by %s", label, p, reason)
		}
		return nil
	}
	if err := check(in.ListenPort, "public", false); err != nil {
		return err
	}
	if in.Mode != model.SshModeNormal {
		if err := check(in.BackendSshPort, "backend", false); err != nil {
			return err
		}
	}
	if in.UdpRelayPort > 0 {
		if err := check(in.UdpRelayPort, "UDP relay", true); err != nil {
			return err
		}
	}

	// Live probe of the public port if it is new to us.
	prevSamePublic := false
	prevSameUDP := false
	if in.Id > 0 {
		if cur, err := s.GetInbound(in.Id); err == nil && cur.Enable {
			prevSamePublic = cur.ListenPort == in.ListenPort
			prevSameUDP = in.UdpRelayPort > 0 && cur.UdpRelayPort == in.UdpRelayPort
		}
	}
	if !prevSamePublic && !sshSys.portFree(in.ListenPort) {
		return fmt.Errorf("public port %d is currently in use by another process", in.ListenPort)
	}

	if in.UdpRelayPort > 0 && !prevSameUDP {
		// An identical UDPGW port may already be intentionally shared by another
		// inbound. In that case the existing listener is expected and must not be
		// treated as a conflict.
		shared := false
		var others []model.SshInbound
		if err := database.GetDB().Where("id <> ? AND udp_relay_port = ?", in.Id, in.UdpRelayPort).Find(&others).Error; err == nil {
			for _, other := range others {
				if other.Enable {
					shared = true
					break
				}
			}
		}
		if !shared && !sshSys.portFree(in.UdpRelayPort) {
			return fmt.Errorf("UDP relay port %d is currently in use by another process", in.UdpRelayPort)
		}
	}
	return nil
}

// allocateGatewayPort chooses a free loopback port for TLS+payload mode while
// avoiding ports already reserved in the panel and the inbound's UDPGW port.
func (s *SshManagerService) allocateGatewayPort(in *model.SshInbound) error {
	reserved := s.collectReservedPorts(in.Id)
	for tries := 0; tries < 20; tries++ {
		gp, err := sshSys.freeLocalPort()
		if err != nil {
			return err
		}
		if gp == in.ListenPort || gp == in.BackendSshPort || gp == in.UdpRelayPort {
			continue
		}
		if _, clash := reserved[gp]; clash {
			continue
		}
		in.GatewayPort = gp
		return nil
	}
	return errors.New("could not allocate a conflict-free payload gateway port")
}

// ---------------------------------------------------------------------------
// Inbound CRUD
// ---------------------------------------------------------------------------

func (s *SshManagerService) GetInbounds() ([]model.SshInbound, error) {
	var list []model.SshInbound
	err := database.GetDB().Order("id asc").Find(&list).Error
	return list, err
}

func (s *SshManagerService) GetInbound(id int) (*model.SshInbound, error) {
	in := &model.SshInbound{}
	err := database.GetDB().First(in, id).Error
	if err != nil {
		return nil, err
	}
	return in, nil
}

func (s *SshManagerService) AddInbound(in *model.SshInbound) (*model.SshInbound, error) {
	if err := s.validateInbound(in); err != nil {
		return nil, err
	}
	if err := s.checkInboundPorts(in); err != nil {
		return nil, err
	}
	// Auto-assign a loopback gateway port for payload mode.
	if in.Mode == model.SshModeTlsPayload && in.GatewayPort == 0 {
		if err := s.allocateGatewayPort(in); err != nil {
			return nil, err
		}
	}
	in.Id = 0
	if err := database.GetDB().Create(in).Error; err != nil {
		return nil, err
	}
	logger.Infof("ssh-manager: inbound created id=%d name=%q mode=%s port=%d", in.Id, in.Name, in.Mode, in.ListenPort)
	if err := s.Reconcile(); err != nil {
		// Do not report a failed create while leaving a DB row behind. Restore
		// the previous desired state and make a best-effort runtime rollback.
		_ = database.GetDB().Delete(&model.SshInbound{}, in.Id).Error
		_ = s.Reconcile()
		return in, err
	}
	return in, nil
}

func (s *SshManagerService) UpdateInbound(in *model.SshInbound) (*model.SshInbound, error) {
	cur, err := s.GetInbound(in.Id)
	if err != nil {
		return nil, errors.New("inbound not found")
	}
	if err := s.validateInbound(in); err != nil {
		return nil, err
	}
	if err := s.checkInboundPorts(in); err != nil {
		return nil, err
	}
	if in.Mode == model.SshModeTlsPayload {
		if in.GatewayPort == 0 {
			if cur.GatewayPort != 0 && cur.GatewayPort != in.UdpRelayPort {
				in.GatewayPort = cur.GatewayPort
			} else {
				if err := s.allocateGatewayPort(in); err != nil {
					return nil, err
				}
			}
		}
		if in.UdpRelayPort > 0 && in.GatewayPort == in.UdpRelayPort {
			return nil, errors.New("UDP relay port must differ from the payload gateway port")
		}
	} else {
		in.GatewayPort = 0
	}
	in.CreatedAt = cur.CreatedAt
	if err := database.GetDB().Save(in).Error; err != nil {
		return nil, err
	}
	logger.Infof("ssh-manager: inbound updated id=%d name=%q mode=%s port=%d", in.Id, in.Name, in.Mode, in.ListenPort)
	if err := s.Reconcile(); err != nil {
		// Save() already changed the row, so restore the exact previous model
		// when the host reconciliation fails. This keeps the panel and live SSH
		// configuration from drifting apart after an unsuccessful edit.
		_ = database.GetDB().Save(cur).Error
		_ = s.Reconcile()
		return in, err
	}
	return in, nil
}

func (s *SshManagerService) DelInbound(id int) error {
	cur, err := s.GetInbound(id)
	if err != nil {
		return errors.New("inbound not found")
	}
	if err := database.GetDB().Delete(&model.SshInbound{}, id).Error; err != nil {
		return err
	}
	logger.Infof("ssh-manager: inbound deleted id=%d", id)
	if err := s.Reconcile(); err != nil {
		// The old implementation deleted first and returned the reconcile
		// error, so the UI said "Failed to delete" even though the row was
		// already gone. Restore the row on failure and reconcile back to the
		// previous runtime state instead.
		if rerr := database.GetDB().Create(cur).Error; rerr != nil {
			return fmt.Errorf("%v; additionally failed to restore deleted inbound: %v", err, rerr)
		}
		_ = s.Reconcile()
		return err
	}
	return nil
}

func (s *SshManagerService) SetInboundEnable(id int, enable bool) error {
	cur, err := s.GetInbound(id)
	if err != nil {
		return errors.New("inbound not found")
	}
	if err := database.GetDB().Model(&model.SshInbound{}).Where("id = ?", id).Update("enable", enable).Error; err != nil {
		return err
	}
	logger.Infof("ssh-manager: inbound id=%d enable=%v", id, enable)
	if err := s.Reconcile(); err != nil {
		_ = database.GetDB().Model(&model.SshInbound{}).Where("id = ?", id).Update("enable", cur.Enable).Error
		_ = s.Reconcile()
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// User CRUD (backed by real Linux accounts in the xui-ssh-users group)
// ---------------------------------------------------------------------------

func (s *SshManagerService) GetUsers() ([]model.SshUser, error) {
	var list []model.SshUser
	if err := database.GetDB().Order("id asc").Find(&list).Error; err != nil {
		return nil, err
	}
	// Decrypt passwords for display (panel-admin only context).
	for i := range list {
		if pw, err := s.decryptPassword(list[i].PasswordEnc); err == nil {
			list[i].Password = pw
		}
	}
	return list, nil
}

func (s *SshManagerService) AddUser(u *model.SshUser) error {
	if err := validateUserLimits(u); err != nil {
		return err
	}
	u.Username = strings.TrimSpace(u.Username)
	if err := validUsername(u.Username); err != nil {
		return err
	}
	if isProtectedUser(u.Username) {
		return errors.New("refusing to manage a protected system user")
	}
	if err := validPassword(u.Password); err != nil {
		return err
	}
	// DB uniqueness
	var count int64
	database.GetDB().Model(&model.SshUser{}).Where("username = ?", u.Username).Count(&count)
	if count > 0 {
		return errors.New("a managed user with that name already exists")
	}
	if sshSys.userExists(u.Username) {
		return errors.New("a system user with that name already exists")
	}

	if err := sshSys.ensureGroup(); err != nil {
		return err
	}
	if err := sshSys.createUser(u.Username); err != nil {
		return err
	}
	if err := sshSys.setPassword(u.Username, u.Password); err != nil {
		_ = sshSys.deleteUser(u.Username) // roll back the half-created account
		return err
	}
	if !u.Enable {
		_ = sshSys.lockUser(u.Username)
	} else {
		sshSys.setExpiry(u.Username, msToChageDate(u.ExpiryTime))
	}

	enc, err := s.encryptPassword(u.Password)
	if err != nil {
		return err
	}
	row := model.SshUser{
		Username: u.Username, PasswordEnc: enc, Enable: u.Enable, ExpiryTime: u.ExpiryTime, Note: u.Note,
		TrafficLimit: u.TrafficLimit, ResetFlow: u.ResetFlow, LastResetTime: time.Now().UnixMilli(),
		SpeedLimit: u.SpeedLimit, DownloadMbps: u.DownloadMbps, UploadMbps: u.UploadMbps,
	}
	if err := database.GetDB().Create(&row).Error; err != nil {
		return err
	}
	u.Id = row.Id
	logger.Infof("ssh-manager: user created %q (enabled=%v)", u.Username, u.Enable)
	return nil
}

func (s *SshManagerService) UpdateUser(u *model.SshUser) error {
	if err := validateUserLimits(u); err != nil {
		return err
	}
	cur := &model.SshUser{}
	if err := database.GetDB().First(cur, u.Id).Error; err != nil {
		return errors.New("user not found")
	}
	if isProtectedUser(cur.Username) {
		return errors.New("refusing to manage a protected system user")
	}
	// Guard: only ever touch accounts that are members of our group.
	if sshSys.userExists(cur.Username) && !sshSys.inManagedGroup(cur.Username) {
		return errors.New("system user is not managed by the panel (not in " + sshUsersGroup + ")")
	}

	// Password change is optional on edit.
	if strings.TrimSpace(u.Password) != "" {
		if err := validPassword(u.Password); err != nil {
			return err
		}
		if err := sshSys.setPassword(cur.Username, u.Password); err != nil {
			return err
		}
		enc, err := s.encryptPassword(u.Password)
		if err != nil {
			return err
		}
		cur.PasswordEnc = enc
	}

	cur.Enable = u.Enable
	cur.ExpiryTime = u.ExpiryTime
	cur.Note = u.Note
	cur.TrafficLimit = u.TrafficLimit
	cur.ResetFlow = u.ResetFlow
	cur.SpeedLimit = u.SpeedLimit
	cur.DownloadMbps = u.DownloadMbps
	cur.UploadMbps = u.UploadMbps

	if u.Enable {
		if err := sshSys.unlockUser(cur.Username, msToChageDate(u.ExpiryTime)); err != nil {
			return err
		}
	} else {
		if err := sshSys.lockUser(cur.Username); err != nil {
			return err
		}
	}

	if err := database.GetDB().Save(cur).Error; err != nil {
		return err
	}
	logger.Infof("ssh-manager: user updated %q (enabled=%v)", cur.Username, cur.Enable)
	return nil
}

func (s *SshManagerService) SetUserEnable(id int, enable bool) error {
	cur := &model.SshUser{}
	if err := database.GetDB().First(cur, id).Error; err != nil {
		return errors.New("user not found")
	}
	if isProtectedUser(cur.Username) {
		return errors.New("refusing to manage a protected system user")
	}
	if sshSys.userExists(cur.Username) && !sshSys.inManagedGroup(cur.Username) {
		return errors.New("system user is not managed by the panel")
	}
	if enable {
		if err := sshSys.unlockUser(cur.Username, msToChageDate(cur.ExpiryTime)); err != nil {
			return err
		}
	} else {
		if err := sshSys.lockUser(cur.Username); err != nil {
			return err
		}
	}
	if err := database.GetDB().Model(&model.SshUser{}).Where("id = ?", id).Update("enable", enable).Error; err != nil {
		return err
	}
	logger.Infof("ssh-manager: user id=%d enable=%v", id, enable)
	return nil
}

func (s *SshManagerService) DelUser(id int) error {
	cur := &model.SshUser{}
	if err := database.GetDB().First(cur, id).Error; err != nil {
		return errors.New("user not found")
	}
	if isProtectedUser(cur.Username) {
		return errors.New("refusing to delete a protected system user")
	}
	// Only delete the OS account if it is one of ours.
	if sshSys.userExists(cur.Username) {
		if !sshSys.inManagedGroup(cur.Username) {
			return errors.New("system user is not managed by the panel; not deleting")
		}
		if err := sshSys.deleteUser(cur.Username); err != nil {
			return err
		}
	}
	if err := database.GetDB().Delete(&model.SshUser{}, id).Error; err != nil {
		return err
	}
	logger.Infof("ssh-manager: user deleted %q", cur.Username)
	return nil
}

// ---------------------------------------------------------------------------
// Reconcile: make the live host match the enabled inbounds.
// ---------------------------------------------------------------------------

func (s *SshManagerService) Reconcile() error {
	inbounds, err := s.GetInbounds()
	if err != nil {
		return err
	}

	var sshdPorts []int
	var stunnelSvcs []stunnelSvc
	desiredGateways := map[int]gatewaySpec{} // key: inbound ID
	banners := map[int]string{}              // sshd local port -> banner file
	udpRelayPorts := map[int]int{}           // inbound ID -> udpgw port

	for i := range inbounds {
		in := inbounds[i]
		if !in.Enable {
			continue
		}
		// Persist an optional banner and map it to the sshd-side port the
		// client's session actually lands on.
		if strings.TrimSpace(in.Banner) != "" {
			if bp, err := sshSys.writeBanner(in.Id, in.Banner); err == nil && bp != "" {
				sshdLocalPort := in.ListenPort
				if in.Mode != model.SshModeNormal {
					sshdLocalPort = in.BackendSshPort
				}
				banners[sshdLocalPort] = bp
			}
		}
		// Optional UDP relay (badvpn-udpgw) — runs on loopback, reachable via SSH tunnel.
		if in.UdpRelayPort > 0 {
			udpRelayPorts[in.Id] = in.UdpRelayPort
		}

		switch in.Mode {
		case model.SshModeNormal:
			sshdPorts = append(sshdPorts, in.ListenPort)
			sshSys.allowPort(in.ListenPort)

		case model.SshModeTlsSni:
			sshdPorts = append(sshdPorts, in.BackendSshPort)
			cf, kf, cerr := s.resolveCert(&in)
			if cerr != nil {
				logger.Warningf("ssh-manager: inbound %d cert error: %v", in.Id, cerr)
				continue
			}
			stunnelSvcs = append(stunnelSvcs, stunnelSvc{
				Name:        fmt.Sprintf("svc-%d", in.Id),
				AcceptPort:  in.ListenPort,
				ConnectPort: in.BackendSshPort,
				CertFile:    cf,
				KeyFile:     kf,
			})
			sshSys.allowPort(in.ListenPort)

		case model.SshModeTlsPayload:
			sshdPorts = append(sshdPorts, in.BackendSshPort)
			cf, kf, cerr := s.resolveCert(&in)
			if cerr != nil {
				logger.Warningf("ssh-manager: inbound %d cert error: %v", in.Id, cerr)
				continue
			}
			stunnelSvcs = append(stunnelSvcs, stunnelSvc{
				Name:        fmt.Sprintf("svc-%d", in.Id),
				AcceptPort:  in.ListenPort,
				ConnectPort: in.GatewayPort,
				CertFile:    cf,
				KeyFile:     kf,
			})
			desiredGateways[in.Id] = gatewaySpec{bindIP: "127.0.0.1", listen: in.GatewayPort, backend: in.BackendSshPort}
			sshSys.allowPort(in.ListenPort)

		case model.SshModePayloadOnly:
			// Plain TCP: payload gateway binds directly on the public port — no stunnel, no TLS.
			sshdPorts = append(sshdPorts, in.BackendSshPort)
			desiredGateways[in.Id] = gatewaySpec{bindIP: "0.0.0.0", listen: in.ListenPort, backend: in.BackendSshPort}
			sshSys.allowPort(in.ListenPort)
		}
	}

	// 1) OpenSSH ports (validated + rolled back inside applySshdPorts).
	if err := sshSys.applySshdPorts(sshdPorts, banners); err != nil {
		return err
	}

	// 2) Payload gateways: start desired, stop the rest.
	s.reconcileGateways(desiredGateways)

	// 3) stunnel services.
	if len(stunnelSvcs) > 0 && !sshSys.stunnelInstalled() {
		logger.Warning("ssh-manager: TLS inbound(s) enabled but stunnel is not installed; run: apt-get install -y stunnel4")
	} else {
		if err := sshSys.writeStunnel(stunnelSvcs); err != nil {
			return err
		}
	}

	// 4) UDP relay. The first enable performs complete VPS-side setup
	// (install/build badvpn + persistent service). Treat setup failure as a
	// reconcile failure so CRUD rollback never leaves the UI claiming that an
	// inbound has working UDP when no listener exists.
	if err := reconcileUdpRelays(udpRelayPorts); err != nil {
		return fmt.Errorf("UDP relay setup: %w", err)
	}

	logger.Infof("ssh-manager: reconciled (%d ssh ports, %d stunnel svc, %d gateways, %d udpgw)",
		len(sshdPorts), len(stunnelSvcs), len(desiredGateways), len(udpRelayPorts))
	return nil
}

func (s *SshManagerService) reconcileGateways(desired map[int]gatewaySpec) {
	sshRuntimeMu.Lock()
	defer sshRuntimeMu.Unlock()

	// Stop gateways no longer desired or whose spec changed.
	for id, g := range sshGateways {
		want, ok := desired[id]
		if !ok || want.listen != g.listen || want.backend != g.backend || want.bindIP != g.bindIP {
			g.stop()
			delete(sshGateways, id)
		}
	}
	// Start newly desired gateways.
	for id, spec := range desired {
		if _, running := sshGateways[id]; running {
			continue
		}
		g := newPayloadGateway(id, spec.bindIP, spec.listen, spec.backend)
		if err := g.start(); err != nil {
			logger.Warningf("ssh-manager: gateway start failed for inbound %d: %v", id, err)
			continue
		}
		sshGateways[id] = g
	}
}

func (s *SshManagerService) resolveCert(in *model.SshInbound) (string, string, error) {
	if in.CertMode == model.SshCertExisting {
		cf, err := cleanCertPath(in.CertFile)
		if err != nil {
			return "", "", err
		}
		kf, err := cleanCertPath(in.KeyFile)
		if err != nil {
			return "", "", err
		}
		return cf, kf, nil
	}
	return sshSys.selfSignedCert(in.Id, in.Host)
}

// ---------------------------------------------------------------------------
// Runtime lifecycle (called from web server start/stop)
// ---------------------------------------------------------------------------

// InitRuntime brings the host into line with the stored config at panel start.
// Failures are logged but never abort panel startup.
func (s *SshManagerService) InitRuntime() {
	if !LicenseRuntimeAllowed() {
		logger.Warning("ssh-manager: runtime not started because the 4x-ui license is not active")
		return
	}
	if err := sshSys.ensureGroup(); err != nil {
		logger.Warning("ssh-manager: ensure group failed:", err)
	}
	if err := s.Reconcile(); err != nil {
		logger.Warning("ssh-manager: initial reconcile failed:", err)
	}
	s.startLimitRuntime()
}

// StopRuntime tears down in-process payload gateways and non-systemd UDP relay fallbacks.
// Persistent xui-udpgw@ units intentionally survive a panel restart/update.
func (s *SshManagerService) StopRuntime() {
	stopLimitRuntime()
	sshRuntimeMu.Lock()
	defer sshRuntimeMu.Unlock()
	for port, g := range sshGateways {
		g.stop()
		delete(sshGateways, port)
	}
	StopAllUdpRelays()
}

// SuspendForLicense disables the paid SSH runtime without changing the desired
// enabled/disabled state stored in the database. Managed accounts are password
// locked, while the host's own/root SSH access is never touched.
func (s *SshManagerService) SuspendForLicense() {
	s.StopRuntime()
	sshSys.stopStunnel()
	var users []model.SshUser
	if err := database.GetDB().Where("enable = ?", true).Find(&users).Error; err != nil {
		logger.Warning("ssh-manager: load users for license suspension:", err)
		return
	}
	for i := range users {
		u := &users[i]
		if isProtectedUser(u.Username) || !sshSys.userExists(u.Username) || !sshSys.inManagedGroup(u.Username) {
			continue
		}
		if err := sshSys.lockUser(u.Username); err != nil {
			logger.Warningf("ssh-manager: license suspension could not lock %s: %v", u.Username, err)
		}
	}
	logger.Info("ssh-manager: paid SSH runtime suspended because license is inactive")
}

// RestoreAfterLicense restores only users that are still enabled and have not
// exceeded their own expiry/traffic limit, then rebuilds the SSH runtime.
func (s *SshManagerService) RestoreAfterLicense() {
	if !LicenseRuntimeAllowed() {
		return
	}
	var users []model.SshUser
	if err := database.GetDB().Where("enable = ?", true).Find(&users).Error; err != nil {
		logger.Warning("ssh-manager: load users for license restore:", err)
		return
	}
	now := time.Now().UnixMilli()
	for i := range users {
		u := &users[i]
		if u.ExpiryTime > 0 && now >= u.ExpiryTime {
			_ = database.GetDB().Model(&model.SshUser{}).Where("id = ?", u.Id).Update("enable", false).Error
			continue
		}
		if u.TrafficLimit > 0 && u.TrafficUsed >= u.TrafficLimit {
			_ = database.GetDB().Model(&model.SshUser{}).Where("id = ?", u.Id).Update("enable", false).Error
			continue
		}
		if isProtectedUser(u.Username) || !sshSys.userExists(u.Username) || !sshSys.inManagedGroup(u.Username) {
			continue
		}
		if err := sshSys.unlockUser(u.Username, msToChageDate(u.ExpiryTime)); err != nil {
			logger.Warningf("ssh-manager: license restore could not unlock %s: %v", u.Username, err)
		}
	}
	s.InitRuntime()
	logger.Info("ssh-manager: paid SSH runtime restored after license validation")
}

// SystemStatus reports environment facts the UI surfaces to the admin.
func (s *SshManagerService) SystemStatus() map[string]any {
	return map[string]any{
		"stunnelInstalled": sshSys.stunnelInstalled(),
		"badvpnInstalled":  BadvpnInstalled(),
		"group":            sshUsersGroup,
	}
}
