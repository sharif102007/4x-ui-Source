package service

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func listenLocal(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func startPayloadTestFront(t *testing.T, backendPort int) (net.Listener, int) {
	t.Helper()
	ln := listenLocal(t)
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			handlePayloadBypassConnection(conn, backendPort)
		}
	}()
	return ln, port
}

func TestPayloadBypassConsumesInjectorHeader(t *testing.T) {
	backendLn := listenLocal(t)
	defer backendLn.Close()
	backendPort := backendLn.Addr().(*net.TCPAddr).Port

	gotBackend := make(chan []byte, 1)
	go func() {
		conn, err := backendLn.Accept()
		if err != nil {
			gotBackend <- nil
			return
		}
		defer conn.Close()
		buf := make([]byte, len("EARLYHELLO"))
		_, _ = io.ReadFull(conn, buf)
		gotBackend <- buf
		_, _ = conn.Write([]byte("WORLD"))
	}()

	frontLn, frontPort := startPayloadTestFront(t, backendPort)
	defer frontLn.Close()

	client, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(frontPort), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	payload := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\nService: SSH\r\nMode: Bypass\r\n\r\nEARLY"
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	var response bytes.Buffer
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		response.WriteString(line)
		if strings.HasSuffix(response.String(), "\r\n\r\n") {
			break
		}
	}
	if !strings.HasPrefix(response.String(), "HTTP/1.1 101 Switching Protocols") {
		t.Fatalf("unexpected payload response: %q", response.String())
	}
	if _, err := client.Write([]byte("HELLO")); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-gotBackend:
		if string(got) != "EARLYHELLO" {
			t.Fatalf("backend got %q, want post-header payload only", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backend did not receive tunneled bytes")
	}

	reply := make([]byte, len("WORLD"))
	if _, err := io.ReadFull(reader, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != "WORLD" {
		t.Fatalf("client got %q", reply)
	}
}

func TestPayloadBypassPassesRealWebSocketHandshake(t *testing.T) {
	backendLn := listenLocal(t)
	defer backendLn.Close()
	backendPort := backendLn.Addr().(*net.TCPAddr).Port

	gotHeader := make(chan string, 1)
	go func() {
		conn, err := backendLn.Accept()
		if err != nil {
			gotHeader <- ""
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		var header strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				gotHeader <- ""
				return
			}
			header.WriteString(line)
			if strings.HasSuffix(header.String(), "\r\n\r\n") {
				break
			}
		}
		gotHeader <- header.String()
		_, _ = conn.Write([]byte("HTTP/1.1 101 Backend\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
	}()

	frontLn, frontPort := startPayloadTestFront(t, backendPort)
	defer frontLn.Close()
	client, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(frontPort), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	request := "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGVzdA==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := client.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-gotHeader:
		if got != request {
			t.Fatalf("backend handshake changed:\n%q\nwant:\n%q", got, request)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backend did not receive WebSocket handshake")
	}

	resp, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if resp != "HTTP/1.1 101 Backend\r\n" {
		t.Fatalf("gateway synthesized response for direct WS: %q", resp)
	}
}

func TestPayloadBypassPassesTLSClientHelloPrefix(t *testing.T) {
	backendLn := listenLocal(t)
	defer backendLn.Close()
	backendPort := backendLn.Addr().(*net.TCPAddr).Port

	gotBackend := make(chan []byte, 1)
	go func() {
		conn, err := backendLn.Accept()
		if err != nil {
			gotBackend <- nil
			return
		}
		defer conn.Close()
		buf := make([]byte, 7)
		_, _ = io.ReadFull(conn, buf)
		gotBackend <- buf
		_, _ = conn.Write([]byte("TLSOK"))
	}()

	frontLn, frontPort := startPayloadTestFront(t, backendPort)
	defer frontLn.Close()
	client, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(frontPort), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Minimal TLS-record-shaped prefix; the gateway only needs to recognize the
	// record layer and pass it through. Xray performs the real TLS handshake.
	prefix := []byte{0x16, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00}
	if _, err := client.Write(prefix); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-gotBackend:
		if !bytes.Equal(got, prefix) {
			t.Fatalf("backend TLS prefix changed: %v want %v", got, prefix)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backend did not receive TLS passthrough bytes")
	}

	reply := make([]byte, len("TLSOK"))
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != "TLSOK" {
		t.Fatalf("client got %q", reply)
	}
}
