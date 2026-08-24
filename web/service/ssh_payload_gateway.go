package service

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sharif102007/4x-ui/v2/logger"
)

// payloadGateway is the local hop for ssh_tls_payload and ssh_payload_only inbounds.
//
//	ssh_tls_payload:  stunnel(TLS) -> payloadGateway(127.0.0.1:listen) -> OpenSSH backend
//	ssh_payload_only: payloadGateway(0.0.0.0:listen) -> OpenSSH backend  [no TLS]
//
// Tolerant: a connection beginning with the raw SSH banner (no HTTP payload)
// is proxied directly, so payload is always optional.
type payloadGateway struct {
	id       int
	bindIP   string // "127.0.0.1" behind stunnel, "0.0.0.0" for plain-TCP public mode
	listen   int
	backend  int
	ln       net.Listener
	closing  chan struct{}
	wg       sync.WaitGroup
	onceStop sync.Once

	// conns tracks every live client connection so stop() can close them.
	// Closing the listener only prevents new connections; an established SSH
	// tunnel stays open for as long as the user keeps it, so shutdown must
	// terminate them rather than wait for them.
	connMu sync.Mutex
	conns  map[net.Conn]struct{}
}

const (
	payloadHeaderLimit = 16 * 1024
	payloadReadTimeout = 15 * time.Second
	dialTimeout        = 10 * time.Second
)

func newPayloadGateway(id int, bindIP string, listen, backend int) *payloadGateway {
	if bindIP == "" {
		bindIP = "127.0.0.1"
	}
	return &payloadGateway{
		id:      id,
		bindIP:  bindIP,
		listen:  listen,
		backend: backend,
		closing: make(chan struct{}),
		conns:   make(map[net.Conn]struct{}),
	}
}

func (g *payloadGateway) start() error {
	bindAddr := fmt.Sprintf("%s:%d", g.bindIP, g.listen)
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("payload gateway listen %s: %w", bindAddr, err)
	}
	g.ln = ln
	g.wg.Add(1)
	go g.acceptLoop()
	logger.Infof("ssh-manager: payload gateway #%d up %s -> 127.0.0.1:%d", g.id, bindAddr, g.backend)
	return nil
}

func (g *payloadGateway) trackConn(c net.Conn) bool {
	g.connMu.Lock()
	defer g.connMu.Unlock()
	if g.conns == nil {
		return false // stop() already ran
	}
	g.conns[c] = struct{}{}
	return true
}

func (g *payloadGateway) untrackConn(c net.Conn) {
	g.connMu.Lock()
	defer g.connMu.Unlock()
	if g.conns != nil {
		delete(g.conns, c)
	}
}

// closeConns terminates every live tunnel. Setting a deadline in the past first
// unblocks any handler currently parked in a read or write on that socket.
func (g *payloadGateway) closeConns() int {
	g.connMu.Lock()
	conns := g.conns
	g.conns = nil
	g.connMu.Unlock()
	for c := range conns {
		_ = c.SetDeadline(time.Now())
		_ = c.Close()
	}
	return len(conns)
}

func (g *payloadGateway) stop() {
	g.onceStop.Do(func() {
		close(g.closing)
		if g.ln != nil {
			_ = g.ln.Close()
		}
		// Previously this waited for every in-flight connection to end on its
		// own. With a user connected over SSH that never happened, so panel
		// shutdown hung until systemd killed it.
		if n := g.closeConns(); n > 0 {
			logger.Infof("ssh-manager: gateway #%d closing %d live connection(s)", g.id, n)
		}
	})
	waitWithTimeout(&g.wg, fmt.Sprintf("ssh payload gateway #%d", g.id))
}

func (g *payloadGateway) acceptLoop() {
	defer g.wg.Done()
	for {
		conn, err := g.ln.Accept()
		if err != nil {
			select {
			case <-g.closing:
				return
			default:
				// transient accept error; brief backoff
				time.Sleep(50 * time.Millisecond)
				continue
			}
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(true)
		}
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			if !g.trackConn(conn) {
				_ = conn.Close()
				return
			}
			defer g.untrackConn(conn)
			g.handle(conn)
		}()
	}
}

func (g *payloadGateway) handle(client net.Conn) {
	defer client.Close()

	br := bufio.NewReader(client)

	// Peek the first byte to decide whether this looks like an HTTP-style
	// payload or a raw SSH client.
	_ = client.SetReadDeadline(time.Now().Add(payloadReadTimeout))
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	_ = client.SetReadDeadline(time.Time{})

	var leftover []byte // bytes already consumed from client that belong to SSH

	if isHTTPStart(first[0]) {
		consumed, reply, ok := consumePayload(br, client)
		if !ok {
			return
		}
		if len(reply) > 0 {
			if _, err := client.Write(reply); err != nil {
				return
			}
		}
		leftover = consumed
	}

	// Dial backend OpenSSH.
	backend, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", g.backend), dialTimeout)
	if err != nil {
		logger.Warningf("ssh-manager: gateway #%d backend dial failed: %v", g.id, err)
		return
	}
	if tcp, ok := backend.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	defer backend.Close()

	// Flush any buffered/leftover client bytes to backend first.
	if len(leftover) > 0 {
		if _, err := backend.Write(leftover); err != nil {
			return
		}
	}
	// Anything still buffered in br (already read from socket) must go too.
	if n := br.Buffered(); n > 0 {
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err == nil {
			if _, err := backend.Write(buf); err != nil {
				return
			}
		}
	}

	splice(client, backend)
}

// isHTTPStart returns true if a byte could begin an HTTP request line
// (CONNECT/GET/POST/PUT/HEAD/OPTIONS/DELETE/TRACE/PATCH).
func isHTTPStart(b byte) bool {
	switch b {
	case 'C', 'G', 'P', 'H', 'O', 'D', 'T':
		return true
	}
	return false
}

// consumePayload reads one HTTP-style preamble up to the blank-line terminator,
// returns any body bytes already read past it (to be forwarded to SSH), and the
// reply that should be written back to the client. It accepts arbitrary Host
// headers (telegram.org, instagram.com, ...) and always routes to the
// configured backend regardless of the requested target.
func consumePayload(br *bufio.Reader, conn net.Conn) (leftover []byte, reply []byte, ok bool) {
	_ = conn.SetReadDeadline(time.Now().Add(payloadReadTimeout))
	defer conn.SetReadDeadline(time.Time{})

	var header bytes.Buffer
	total := 0
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return nil, nil, false
		}
		total += len(line)
		if total > payloadHeaderLimit {
			return nil, nil, false
		}
		header.Write(line)
		// blank line terminates the header block
		if string(line) == "\r\n" || string(line) == "\n" {
			break
		}
	}

	method, isWebsocket := classifyPayload(header.String())

	switch {
	case method == "CONNECT":
		reply = []byte("HTTP/1.1 200 Connection established\r\n\r\n")
	case isWebsocket:
		reply = []byte("HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	default:
		// GET / POST and friends: a plain 200 keeps most injector templates happy.
		reply = []byte("HTTP/1.1 200 OK\r\n\r\n")
	}
	return nil, reply, true
}

// classifyPayload extracts the request method and whether it is a WebSocket
// upgrade. Robust to leading whitespace and arbitrary header ordering.
func classifyPayload(header string) (method string, websocket bool) {
	lines := strings.Split(header, "\n")
	if len(lines) > 0 {
		fields := strings.Fields(strings.TrimSpace(lines[0]))
		if len(fields) > 0 {
			method = strings.ToUpper(fields[0])
		}
	}
	low := strings.ToLower(header)
	if strings.Contains(low, "upgrade: websocket") ||
		(strings.Contains(low, "upgrade:") && strings.Contains(low, "websocket")) {
		websocket = true
	}
	return method, websocket
}

// splice copies bytes bidirectionally until either side closes.
func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		// half-close so the peer sees EOF
		if c, ok := dst.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}
