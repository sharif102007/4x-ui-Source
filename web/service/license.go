package service

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sharif102007/4x-ui/v2/config"
	"github.com/sharif102007/4x-ui/v2/logger"
)

const (
	licenseBaseURL      = "https://licences.srfbrotech.com"
	licenseOfflineGrace = 48 * time.Hour
	licenseHTTPTimeout  = 10 * time.Second
)

// LicenseClaims are the signed claims returned by the private 4x-ui license server.
type LicenseClaims struct {
	LicenseID   int    `json:"license_id"`
	Status      string `json:"status"`
	DeviceID    string `json:"device_id"`
	ActivatedAt int64  `json:"activated_at"`
	ExpiresAt   int64  `json:"expires_at"`
	DaysLeft    int    `json:"days_left"`
	IssuedAt    int64  `json:"issued_at"`
	Server      string `json:"server"`
	Version     string `json:"version"`
}

type licenseDiskState struct {
	LicenseKey   string        `json:"license_key"`
	Token        string        `json:"token,omitempty"`
	Claims       LicenseClaims `json:"claims"`
	PublicKeyPEM string        `json:"public_key_pem,omitempty"`
	LastVerified int64         `json:"last_verified,omitempty"`
	LastAttempt  int64         `json:"last_attempt,omitempty"`
	LastError    string        `json:"last_error,omitempty"`
	PendingState string        `json:"pending_state,omitempty"`
	StartsAt     int64         `json:"starts_at,omitempty"`
}

// LicenseStatus is safe to expose in the local panel. The complete license key is never returned.
type LicenseStatus struct {
	Configured        bool   `json:"configured"`
	Active            bool   `json:"active"`
	State             string `json:"state"`
	Message           string `json:"message"`
	KeyMasked         string `json:"keyMasked"`
	DeviceID          string `json:"deviceId"`
	DeviceShort       string `json:"deviceShort"`
	ActivatedAt       int64  `json:"activatedAt"`
	ExpiresAt         int64  `json:"expiresAt"`
	DaysLeft          int    `json:"daysLeft"`
	LastVerified      int64  `json:"lastVerified"`
	OfflineGraceUntil int64  `json:"offlineGraceUntil"`
	LicenseServer     string `json:"licenseServer"`
	LastError         string `json:"lastError,omitempty"`
	StartsAt          int64  `json:"startsAt,omitempty"`
}

type licenseAPIResponse struct {
	OK        bool          `json:"ok"`
	Error     string        `json:"error"`
	License   LicenseClaims `json:"license"`
	Token     string        `json:"token"`
	StartsAt  int64         `json:"starts_at"`
	ExpiresAt int64         `json:"expires_at"`
}

type LicenseService struct{}

type licenseManager struct {
	mu       sync.Mutex
	loadOnce sync.Once
	state    licenseDiskState
	client   *http.Client
}

var defaultLicenseManager = &licenseManager{
	client: &http.Client{Timeout: licenseHTTPTimeout},
}

var (
	deviceIDOnce   sync.Once
	cachedDeviceID string
)

func licenseStatePath() string {
	return filepath.Join(config.GetDBFolderPath(), "license-client.json")
}

func (m *licenseManager) ensureLoaded() {
	m.loadOnce.Do(func() {
		raw, err := os.ReadFile(licenseStatePath())
		if err != nil {
			if !os.IsNotExist(err) {
				logger.Warningf("license: read local state: %v", err)
			}
			return
		}
		if err := json.Unmarshal(raw, &m.state); err != nil {
			logger.Warningf("license: parse local state: %v", err)
			m.state = licenseDiskState{}
			return
		}

		// Never trust editable cached claims on disk. Rebuild them from the
		// RSA-signed token using the public key that was fetched from the license
		// server during activation/verification. This prevents simple edits to
		// expires_at/status/last_verified from extending a license.
		if strings.TrimSpace(m.state.Token) != "" && strings.TrimSpace(m.state.PublicKeyPEM) != "" {
			key, keyErr := parseRSAPublicKey([]byte(m.state.PublicKeyPEM))
			if keyErr == nil {
				claims, tokenErr := verifySignedLicenseToken(m.state.Token, key)
				if tokenErr == nil {
					m.state.Claims = claims
					if claims.IssuedAt > 0 {
						m.state.LastVerified = claims.IssuedAt
					}
					return
				}
				keyErr = tokenErr
			}
			m.state.LastVerified = 0
			m.state.PendingState = "invalid_local_token"
			m.state.LastError = "Cached license signature is invalid. Online activation is required."
			logger.Warningf("license: cached signature validation failed: %v", keyErr)
		}
	})
}

func (m *licenseManager) saveLocked() error {
	dir := config.GetDBFolderPath()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(&m.state, "", "  ")
	if err != nil {
		return err
	}
	path := licenseStatePath()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0600)
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Chmod(path, 0600)
}

func normalizeLicenseKey(key string) string {
	return strings.ToUpper(strings.TrimSpace(key))
}

func maskLicenseKey(key string) string {
	key = normalizeLicenseKey(key)
	if key == "" {
		return ""
	}
	if len(key) <= 10 {
		return "****"
	}
	return key[:9] + "-****-" + key[len(key)-4:]
}

func readTrimmed(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func computeStableDeviceID() string {
	parts := make([]string, 0, 4)
	if runtime.GOOS == "linux" {
		for _, path := range []string{
			"/etc/machine-id",
			"/sys/class/dmi/id/product_uuid",
			"/sys/class/dmi/id/board_serial",
		} {
			if v := readTrimmed(path); v != "" {
				parts = append(parts, strings.ToLower(v))
			}
		}
	}
	if len(parts) == 0 {
		ifaces, _ := net.Interfaces()
		macs := make([]string, 0, len(ifaces))
		for _, iface := range ifaces {
			if v := strings.TrimSpace(iface.HardwareAddr.String()); v != "" {
				macs = append(macs, strings.ToLower(v))
			}
		}
		sort.Strings(macs)
		parts = append(parts, macs...)
	}
	if len(parts) == 0 {
		host, _ := os.Hostname()
		parts = append(parts, strings.ToLower(strings.TrimSpace(host)))
	}
	seed := "4x-ui-device-v1|" + strings.Join(parts, "|")
	sum := sha256.Sum256([]byte(seed))
	return "4XUI-" + strings.ToUpper(hex.EncodeToString(sum[:]))
}

func stableDeviceID() string {
	deviceIDOnce.Do(func() {
		cachedDeviceID = computeStableDeviceID()
	})
	return cachedDeviceID
}

func deviceName() string {
	host, _ := os.Hostname()
	host = strings.TrimSpace(host)
	if host == "" {
		return "4x-ui VPS"
	}
	if len(host) > 100 {
		host = host[:100]
	}
	return host
}

func (m *licenseManager) publicKeyLocked(force bool) (*rsa.PublicKey, error) {
	if !force && strings.TrimSpace(m.state.PublicKeyPEM) != "" {
		if key, err := parseRSAPublicKey([]byte(m.state.PublicKeyPEM)); err == nil {
			return key, nil
		}
	}
	req, err := http.NewRequest(http.MethodGet, licenseBaseURL+"/api/v1/public-key", nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("license public key: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("license public key: HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	if err != nil {
		return nil, err
	}
	key, err := parseRSAPublicKey(raw)
	if err != nil {
		return nil, err
	}
	m.state.PublicKeyPEM = string(raw)
	return key, nil
}

func parseRSAPublicKey(raw []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("invalid license public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("license public key is not RSA")
	}
	return key, nil
}

func verifySignedLicenseToken(token string, key *rsa.PublicKey) (LicenseClaims, error) {
	var claims LicenseClaims
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return claims, errors.New("invalid license token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return claims, errors.New("invalid license token payload")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims, errors.New("invalid license token signature")
	}
	digest := sha256.Sum256(payload)
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return claims, errors.New("license token signature verification failed")
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return claims, errors.New("invalid signed license claims")
	}
	return claims, nil
}

func (m *licenseManager) verifyTokenLocked(token string) (LicenseClaims, error) {
	key, err := m.publicKeyLocked(false)
	if err == nil {
		if claims, verifyErr := verifySignedLicenseToken(token, key); verifyErr == nil {
			return claims, nil
		}
	}
	// The license server may have rotated its signing key. Refresh it over the
	// pinned HTTPS hostname and retry exactly once.
	key, err = m.publicKeyLocked(true)
	if err != nil {
		return LicenseClaims{}, err
	}
	return verifySignedLicenseToken(token, key)
}

func validateClaims(claims LicenseClaims) error {
	if claims.Status != "active" {
		return fmt.Errorf("license status is %s", claims.Status)
	}
	if claims.DeviceID == "" || claims.DeviceID != stableDeviceID() {
		return errors.New("license device does not match this VPS")
	}
	if claims.ExpiresAt <= time.Now().Unix() {
		return errors.New("license has expired")
	}
	return nil
}

func (m *licenseManager) callLocked(endpoint, key string) (licenseAPIResponse, int, error) {
	var out licenseAPIResponse
	body, _ := json.Marshal(map[string]string{
		"license_key": key,
		"device_id":   stableDeviceID(),
		"device_name": deviceName(),
	})
	req, err := http.NewRequest(http.MethodPost, licenseBaseURL+endpoint, bytes.NewReader(body))
	if err != nil {
		return out, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "4x-ui/"+config.GetVersion()+" license-client")
	resp, err := m.client.Do(req)
	if err != nil {
		return out, 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		return out, resp.StatusCode, err
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, resp.StatusCode, fmt.Errorf("invalid license server response: %w", err)
	}
	return out, resp.StatusCode, nil
}

func friendlyLicenseError(code string) string {
	switch code {
	case "invalid_license":
		return "Invalid license key."
	case "license_suspended":
		return "License is suspended. Contact your provider."
	case "license_not_started":
		return "License is scheduled and has not started yet."
	case "license_expired":
		return "License expired. Please renew your license."
	case "license_already_bound", "device_mismatch":
		return "This license is already bound to another VPS. Ask the provider to reset the device binding."
	case "activation_required":
		return "License needs activation on this VPS."
	case "invalid_device_id":
		return "Unable to create a valid VPS device ID."
	default:
		if code == "" {
			return "License verification failed."
		}
		return "License verification failed: " + code
	}
}

func (m *licenseManager) rememberServerErrorLocked(key string, out licenseAPIResponse) {
	// If the server recognized a real license but refused activation because of
	// state/device, keep the key locally. This lets a customer renew or request a
	// device reset and then press Check Again without having to find the key.
	if out.Error != "" && out.Error != "invalid_license" {
		m.state.LicenseKey = key
	}
	m.state.PendingState = out.Error
	m.state.StartsAt = out.StartsAt
	if out.ExpiresAt > 0 {
		m.state.Claims.ExpiresAt = out.ExpiresAt
	}
	m.state.LastError = friendlyLicenseError(out.Error)
	_ = m.saveLocked()
}

func (m *licenseManager) activate(key string) error {
	m.ensureLoaded()
	m.mu.Lock()
	defer m.mu.Unlock()

	key = normalizeLicenseKey(key)
	if key == "" {
		return errors.New("enter a license key")
	}
	m.state.LastAttempt = time.Now().Unix()
	out, _, err := m.callLocked("/api/v1/activate", key)
	if err != nil {
		m.state.LastError = "License server is unreachable."
		_ = m.saveLocked()
		return fmt.Errorf("license server is unreachable: %w", err)
	}
	if !out.OK {
		m.rememberServerErrorLocked(key, out)
		return errors.New(friendlyLicenseError(out.Error))
	}
	claims, err := m.verifyTokenLocked(out.Token)
	if err != nil {
		m.state.LastError = err.Error()
		_ = m.saveLocked()
		return err
	}
	if err := validateClaims(claims); err != nil {
		m.state.LastError = err.Error()
		_ = m.saveLocked()
		return err
	}
	now := time.Now().Unix()
	verifiedAt := claims.IssuedAt
	if verifiedAt <= 0 {
		verifiedAt = now
	}
	m.state.LicenseKey = key
	m.state.Token = out.Token
	m.state.Claims = claims
	m.state.LastVerified = verifiedAt
	m.state.LastAttempt = now
	m.state.LastError = ""
	m.state.PendingState = ""
	m.state.StartsAt = 0
	if err := m.saveLocked(); err != nil {
		return err
	}
	logger.Infof("license: activated license id=%d on device %s", claims.LicenseID, shortDeviceID(claims.DeviceID))
	return nil
}

func (m *licenseManager) verify() error {
	m.ensureLoaded()
	m.mu.Lock()
	defer m.mu.Unlock()

	key := normalizeLicenseKey(m.state.LicenseKey)
	if key == "" {
		return errors.New("license is not activated")
	}
	m.state.LastAttempt = time.Now().Unix()
	out, _, err := m.callLocked("/api/v1/verify", key)
	if err != nil {
		m.state.LastError = "License server is unreachable."
		_ = m.saveLocked()
		if runtimeAllowedState(m.state, time.Now()) {
			logger.Warningf("license: server unreachable, using offline grace: %v", err)
			return nil
		}
		return fmt.Errorf("license server is unreachable and offline grace is unavailable: %w", err)
	}
	if !out.OK {
		m.rememberServerErrorLocked(key, out)
		return errors.New(friendlyLicenseError(out.Error))
	}
	claims, err := m.verifyTokenLocked(out.Token)
	if err != nil {
		m.state.LastError = err.Error()
		_ = m.saveLocked()
		return err
	}
	if err := validateClaims(claims); err != nil {
		m.state.LastError = err.Error()
		_ = m.saveLocked()
		return err
	}
	now := time.Now().Unix()
	verifiedAt := claims.IssuedAt
	if verifiedAt <= 0 {
		verifiedAt = now
	}
	m.state.Token = out.Token
	m.state.Claims = claims
	m.state.LastVerified = verifiedAt
	m.state.LastAttempt = now
	m.state.LastError = ""
	m.state.PendingState = ""
	m.state.StartsAt = 0
	if err := m.saveLocked(); err != nil {
		return err
	}
	return nil
}

func runtimeAllowedState(state licenseDiskState, now time.Time) bool {
	if normalizeLicenseKey(state.LicenseKey) == "" || state.LastVerified <= 0 {
		return false
	}
	// A definitive response from the license server (expired, suspended,
	// device mismatch, key replaced, scheduled, etc.) overrides the offline
	// cache immediately. Offline grace is only for network/server outages.
	if state.PendingState != "" {
		return false
	}
	if state.Claims.Status != "active" || state.Claims.DeviceID != stableDeviceID() {
		return false
	}
	nowUnix := now.Unix()
	if state.Claims.ExpiresAt <= nowUnix {
		return false
	}
	verifiedAt := state.Claims.IssuedAt
	if verifiedAt <= 0 {
		verifiedAt = state.LastVerified
	}
	if verifiedAt <= 0 || nowUnix-verifiedAt > int64(licenseOfflineGrace/time.Second) {
		return false
	}
	return true
}

func shortDeviceID(id string) string {
	id = strings.TrimSpace(id)
	if len(id) <= 18 {
		return id
	}
	return id[:13] + "..." + id[len(id)-4:]
}

func (m *licenseManager) runtimeAllowed() bool {
	m.ensureLoaded()
	m.mu.Lock()
	defer m.mu.Unlock()
	return runtimeAllowedState(m.state, time.Now())
}

func (m *licenseManager) configured() bool {
	m.ensureLoaded()
	m.mu.Lock()
	defer m.mu.Unlock()
	return normalizeLicenseKey(m.state.LicenseKey) != ""
}

func (m *licenseManager) status() LicenseStatus {
	m.ensureLoaded()
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	allowed := runtimeAllowedState(m.state, now)
	state := m.state.Claims.Status
	if state == "" {
		state = "unlicensed"
	}
	if m.state.PendingState != "" {
		switch m.state.PendingState {
		case "license_not_started":
			state = "scheduled"
		case "license_expired":
			state = "expired"
		case "license_suspended":
			state = "suspended"
		case "license_already_bound", "device_mismatch":
			state = "device_mismatch"
		default:
			state = m.state.PendingState
		}
	}
	if m.state.Claims.ExpiresAt > 0 && m.state.Claims.ExpiresAt <= now.Unix() {
		state = "expired"
		allowed = false
	}
	message := "License key required."
	if allowed {
		message = "License is active."
		if m.state.LastError != "" {
			message = "License is active using the offline grace period."
		}
	} else if m.state.LastError != "" {
		message = m.state.LastError
	} else if state == "expired" {
		message = "License expired. Please renew your license."
	}
	days := 0
	if m.state.Claims.ExpiresAt > now.Unix() {
		days = int((m.state.Claims.ExpiresAt - now.Unix() + 86399) / 86400)
	}
	graceUntil := int64(0)
	verifiedAt := m.state.Claims.IssuedAt
	if verifiedAt <= 0 {
		verifiedAt = m.state.LastVerified
	}
	if verifiedAt > 0 {
		graceUntil = verifiedAt + int64(licenseOfflineGrace/time.Second)
	}
	return LicenseStatus{
		Configured:        normalizeLicenseKey(m.state.LicenseKey) != "",
		Active:            allowed,
		State:             state,
		Message:           message,
		KeyMasked:         maskLicenseKey(m.state.LicenseKey),
		DeviceID:          stableDeviceID(),
		DeviceShort:       shortDeviceID(stableDeviceID()),
		ActivatedAt:       m.state.Claims.ActivatedAt,
		ExpiresAt:         m.state.Claims.ExpiresAt,
		DaysLeft:          days,
		LastVerified:      m.state.LastVerified,
		OfflineGraceUntil: graceUntil,
		LicenseServer:     licenseBaseURL,
		LastError:         m.state.LastError,
		StartsAt:          m.state.StartsAt,
	}
}

// ActivateLicense binds a license to this VPS and stores a signed local cache.
func (LicenseService) ActivateLicense(key string) error {
	return defaultLicenseManager.activate(key)
}

// VerifyLicense verifies the stored license online, falling back to a maximum
// 48-hour signed offline grace period only when the server cannot be reached.
func (LicenseService) VerifyLicense() error {
	return defaultLicenseManager.verify()
}

func (LicenseService) RuntimeAllowed() bool {
	return defaultLicenseManager.runtimeAllowed()
}

func (LicenseService) Configured() bool {
	return defaultLicenseManager.configured()
}

func (LicenseService) Status() LicenseStatus {
	return defaultLicenseManager.status()
}

func LicenseRuntimeAllowed() bool {
	return defaultLicenseManager.runtimeAllowed()
}

func LicenseConfigured() bool {
	return defaultLicenseManager.configured()
}

func VerifyStoredLicense() error {
	return defaultLicenseManager.verify()
}
