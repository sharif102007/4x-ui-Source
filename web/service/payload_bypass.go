package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sharif102007/4x-ui/v2/database"
	"github.com/sharif102007/4x-ui/v2/database/model"
	"github.com/sharif102007/4x-ui/v2/logger"
)

const (
	payloadHeaderTimeout = 5 * time.Second
	payloadDialTimeout   = 5 * time.Second
	payloadMaxHeaderSize = 64 * 1024
)

var payloadSwitchingProtocols = []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")

type xrayPayloadGatewayConfig struct {
	InboundID   int
	ListenHost  string
	PublicPort  int
	BackendPort int
}

type xrayPayloadGateway struct {
	cfg xrayPayloadGatewayConfig
	ln  net.Listener
}

type payloadBypassManagerType struct {
	mu       sync.Mutex
	gateways map[int]*xrayPayloadGateway
}

var payloadBypassManager = &payloadBypassManagerType{
	gateways: make(map[int]*xrayPayloadGateway),
}

func normalizePayloadListenHost(host string) string {
	host = strings.TrimSpace(host)
	switch host {
	case "", "0.0.0.0":
		return "0.0.0.0"
	case "::0":
		return "::"
	case "localhost":
		return "127.0.0.1"
	default:
		return host
	}
}

func payloadGatewayConfigForInbound(in *model.Inbound) xrayPayloadGatewayConfig {
	return xrayPayloadGatewayConfig{
		InboundID:   in.Id,
		ListenHost:  normalizePayloadListenHost(in.Listen),
		PublicPort:  in.Port,
		BackendPort: in.PayloadBackendPort,
	}
}

func (c xrayPayloadGatewayConfig) equal(other xrayPayloadGatewayConfig) bool {
	return c.InboundID == other.InboundID &&
		c.ListenHost == other.ListenHost &&
		c.PublicPort == other.PublicPort &&
		c.BackendPort == other.BackendPort
}

func (m *payloadBypassManagerType) Reconcile(in *model.Inbound) error {
	if in == nil {
		return errors.New("payload bypass inbound is nil")
	}
	if !in.Enable || !in.PayloadBypass {
		m.Stop(in.Id)
		return nil
	}
	if err := validatePayloadBypassInbound(in); err != nil {
		return err
	}

	cfg := payloadGatewayConfigForInbound(in)
	addr := net.JoinHostPort(cfg.ListenHost, strconv.Itoa(cfg.PublicPort))

	m.mu.Lock()
	defer m.mu.Unlock()

	if current, ok := m.gateways[in.Id]; ok {
		if current.cfg.equal(cfg) {
			return nil
		}
		_ = current.ln.Close()
		delete(m.gateways, in.Id)
	}

	ln, err := listenPayloadPublic(addr)
	if err != nil {
		return err
	}
	gateway := &xrayPayloadGateway{cfg: cfg, ln: ln}
	m.gateways[in.Id] = gateway
	go gateway.serve()
	logger.Infof("Payload Bypass started for inbound %d: %s -> 127.0.0.1:%d", in.Id, addr, cfg.BackendPort)
	return nil
}

func listenPayloadPublic(addr string) (net.Listener, error) {
	// Xray releases a deleted inbound port very quickly, but on a busy VPS the
	// close can race the panel's replacement listener by a few scheduler ticks.
	// Retry for at most one second so toggling Payload Bypass does not fail on a
	// transient EADDRINUSE. Persistent conflicts still surface to the UI.
	var lastErr error
	for attempt := 0; attempt < 20; attempt++ {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			return ln, nil
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	return nil, fmt.Errorf("payload bypass listen %s: %w", addr, lastErr)
}

func (m *payloadBypassManagerType) removeIfCurrent(gateway *xrayPayloadGateway) {
	if gateway == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if current, ok := m.gateways[gateway.cfg.InboundID]; ok && current == gateway {
		delete(m.gateways, gateway.cfg.InboundID)
	}
}

func (m *payloadBypassManagerType) Stop(id int) {
	if id <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	gateway, ok := m.gateways[id]
	if !ok {
		return
	}
	_ = gateway.ln.Close()
	delete(m.gateways, id)
	logger.Debugf("Payload Bypass stopped for inbound %d", id)
}

func (m *payloadBypassManagerType) StopExcept(keep map[int]struct{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, gateway := range m.gateways {
		if _, ok := keep[id]; ok {
			continue
		}
		_ = gateway.ln.Close()
		delete(m.gateways, id)
		logger.Debugf("Payload Bypass stopped stale inbound %d", id)
	}
}

func (m *payloadBypassManagerType) StopAll() {
	m.StopExcept(map[int]struct{}{})
}

func (g *xrayPayloadGateway) serve() {
	defer payloadBypassManager.removeIfCurrent(g)
	for {
		conn, err := g.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			logger.Debugf("Payload Bypass accept failed for inbound %d: %v", g.cfg.InboundID, err)
			return
		}
		go handlePayloadBypassConnection(conn, g.cfg.BackendPort)
	}
}

func tunePayloadTCPConn(conn net.Conn) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tcp.SetNoDelay(true)
	_ = tcp.SetKeepAlive(true)
	_ = tcp.SetKeepAlivePeriod(30 * time.Second)
}

func looksLikeTLSPayload(buf []byte) bool {
	// TLS handshakes start with a Handshake record (0x16) followed by the
	// legacy record-layer version 0x03xx. Passing these bytes through lets a
	// normal WSS client continue to use the same public port while Payload
	// Bypass is enabled; injected plaintext HTTP payloads still use the 101
	// compatibility path below.
	return len(buf) >= 3 && buf[0] == 0x16 && buf[1] == 0x03
}

func readPayloadPrelude(conn net.Conn) (buffer []byte, headerEnd int, passthrough bool, err error) {
	if err := conn.SetReadDeadline(time.Now().Add(payloadHeaderTimeout)); err != nil {
		return nil, 0, false, err
	}
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		if len(buf) > payloadMaxHeaderSize {
			return nil, 0, false, fmt.Errorf("payload header exceeds %d bytes", payloadMaxHeaderSize)
		}
		if looksLikeTLSPayload(buf) {
			return buf, 0, true, nil
		}
		if idx := bytes.Index(buf, []byte("\r\n\r\n")); idx >= 0 {
			return buf, idx + 4, false, nil
		}
		n, readErr := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if readErr != nil {
			return nil, 0, false, readErr
		}
	}
}

func isDirectWebSocketHandshake(header []byte) bool {
	lower := bytes.ToLower(header)
	// A real RFC6455 WebSocket handshake carries Sec-WebSocket-Key. Payload
	// injectors commonly spoof Upgrade/Connection without this key. Passing
	// genuine handshakes through keeps normal WS clients working even while
	// Payload Bypass is enabled.
	return bytes.Contains(lower, []byte("\r\nsec-websocket-key:"))
}

func dialPayloadBackend(port int) (net.Conn, error) {
	dialer := net.Dialer{Timeout: payloadDialTimeout, KeepAlive: 30 * time.Second}
	conn, err := dialer.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	tunePayloadTCPConn(conn)
	return conn, nil
}

func handlePayloadBypassConnection(client net.Conn, backendPort int) {
	defer client.Close()
	tunePayloadTCPConn(client)

	buffer, headerEnd, passthrough, err := readPayloadPrelude(client)
	if err != nil {
		return
	}

	backend, err := dialPayloadBackend(backendPort)
	if err != nil {
		logger.Debugf("Payload Bypass backend 127.0.0.1:%d unavailable: %v", backendPort, err)
		return
	}
	defer backend.Close()

	// The original Asyncio payload proxy used by the demonstrated workflow
	// consumes the first HTTP payload, answers with a synthetic 101, then
	// forwards only bytes that follow the first CRLFCRLF to the target port.
	// Preserve that behavior for payload injectors. A genuine WebSocket
	// handshake is forwarded untouched so ordinary WS clients also remain
	// compatible with the switch enabled.
	if passthrough {
		if _, err := backend.Write(buffer); err != nil {
			return
		}
	} else if isDirectWebSocketHandshake(buffer[:headerEnd]) {
		if _, err := backend.Write(buffer); err != nil {
			return
		}
	} else {
		if _, err := client.Write(payloadSwitchingProtocols); err != nil {
			return
		}
		if len(buffer) > headerEnd {
			if _, err := backend.Write(buffer[headerEnd:]); err != nil {
				return
			}
		}
	}

	_ = client.SetDeadline(time.Time{})
	_ = backend.SetDeadline(time.Time{})
	proxyPayloadStreams(client, backend)
}

func proxyPayloadStreams(client, backend net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyOneWay := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if tcp, ok := dst.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}

	go copyOneWay(backend, client)
	go copyOneWay(client, backend)
	wg.Wait()
}

type payloadBypassStreamInfo struct {
	Network             string
	AcceptProxyProtocol bool
}

func payloadBypassStream(in *model.Inbound) (payloadBypassStreamInfo, error) {
	if in == nil || strings.TrimSpace(in.StreamSettings) == "" {
		return payloadBypassStreamInfo{}, errors.New("payload bypass requires WebSocket transmission")
	}
	var stream struct {
		Network    string `json:"network"`
		WSSettings struct {
			AcceptProxyProtocol bool `json:"acceptProxyProtocol"`
		} `json:"wsSettings"`
	}
	if err := json.Unmarshal([]byte(in.StreamSettings), &stream); err != nil {
		return payloadBypassStreamInfo{}, fmt.Errorf("parse stream settings for payload bypass: %w", err)
	}
	return payloadBypassStreamInfo{
		Network:             strings.ToLower(strings.TrimSpace(stream.Network)),
		AcceptProxyProtocol: stream.WSSettings.AcceptProxyProtocol,
	}, nil
}

func validatePayloadBypassInbound(in *model.Inbound) error {
	if in == nil || !in.PayloadBypass {
		return nil
	}
	stream, err := payloadBypassStream(in)
	if err != nil {
		return err
	}
	if stream.Network != "ws" {
		return errors.New("payload bypass is available only for WebSocket transmission")
	}
	if stream.AcceptProxyProtocol {
		return errors.New("payload bypass cannot be combined with WebSocket Proxy Protocol")
	}
	if in.Port <= 0 || in.Port > 65535 {
		return fmt.Errorf("invalid payload bypass public port %d", in.Port)
	}
	if in.PayloadBackendPort <= 0 || in.PayloadBackendPort > 65535 {
		return fmt.Errorf("invalid payload bypass backend port %d", in.PayloadBackendPort)
	}
	if in.PayloadBackendPort == in.Port {
		return fmt.Errorf("payload bypass backend port cannot equal public port %d", in.Port)
	}
	return nil
}

func (s *InboundService) allocatePayloadBackendPort(publicPort int) (int, error) {
	db := database.GetDB()
	if db == nil {
		return 0, errors.New("database is not initialized")
	}

	for attempt := 0; attempt < 32; attempt++ {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return 0, fmt.Errorf("allocate payload bypass backend port: %w", err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		if port == publicPort {
			continue
		}

		var count int64
		if err := db.Model(&model.Inbound{}).
			Where("port = ? OR payload_backend_port = ?", port, port).
			Count(&count).Error; err != nil {
			return 0, err
		}
		if count != 0 || s.externalPortOwner(port) != "" {
			continue
		}
		return port, nil
	}
	return 0, errors.New("unable to allocate a free payload bypass backend port")
}

func (s *InboundService) ensurePayloadBypassConfig(in *model.Inbound) error {
	if in == nil {
		return errors.New("inbound is nil")
	}
	if !in.PayloadBypass {
		in.PayloadBackendPort = 0
		return nil
	}
	stream, err := payloadBypassStream(in)
	if err != nil {
		return err
	}
	if stream.Network != "ws" {
		return errors.New("payload bypass is available only for WebSocket transmission")
	}
	if stream.AcceptProxyProtocol {
		return errors.New("payload bypass cannot be combined with WebSocket Proxy Protocol")
	}
	if in.PayloadBackendPort == 0 {
		port, err := s.allocatePayloadBackendPort(in.Port)
		if err != nil {
			return err
		}
		in.PayloadBackendPort = port
	}
	return validatePayloadBypassInbound(in)
}

// ReconcilePayloadBypasses restores all native payload listeners from the DB.
// It is called before Xray starts so the public port remains owned by the panel
// while Xray binds only to each hidden loopback backend port.
func (s *InboundService) ReconcilePayloadBypasses() error {
	db := database.GetDB()
	if db == nil {
		return errors.New("database is not initialized")
	}
	var inbounds []model.Inbound
	if err := db.Find(&inbounds).Error; err != nil {
		return err
	}

	keep := make(map[int]struct{})
	for i := range inbounds {
		in := &inbounds[i]
		if !in.Enable || !in.PayloadBypass {
			continue
		}
		if err := s.ensurePayloadBypassConfig(in); err != nil {
			return fmt.Errorf("inbound %d: %w", in.Id, err)
		}
		if err := db.Model(&model.Inbound{}).Where("id = ?", in.Id).
			Update("payload_backend_port", in.PayloadBackendPort).Error; err != nil {
			return err
		}
		if err := payloadBypassManager.Reconcile(in); err != nil {
			return fmt.Errorf("inbound %d: %w", in.Id, err)
		}
		keep[in.Id] = struct{}{}
	}
	payloadBypassManager.StopExcept(keep)
	return nil
}
