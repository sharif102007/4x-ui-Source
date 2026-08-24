package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sharif102007/4x-ui/v2/util/json_util"
	"github.com/sharif102007/4x-ui/v2/xray"
)

func TestValidateInboundCertsReportsMissingFile(t *testing.T) {
	config := &xray.Config{
		InboundConfigs: []xray.InboundConfig{{
			Tag:            "inbound-tls",
			Port:           443,
			StreamSettings: json_util.RawMessage(`{"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/nonexistent/4xui/fullchain.pem","keyFile":"/nonexistent/4xui/privkey.pem"}]}}`),
		}},
	}
	err := validateInboundCerts(config)
	if err == nil {
		t.Fatal("expected an error naming the missing certificate")
	}
	for _, want := range []string{"inbound-tls", "443", "/nonexistent/4xui/fullchain.pem"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error should mention %q: %v", want, err)
		}
	}
}

func TestValidateInboundCertsPassesForReadableFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	for _, path := range []string{certPath, keyPath} {
		if err := os.WriteFile(path, []byte("not a real pem, only needs to be non-empty"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stream := fmt.Sprintf(`{"security":"tls","tlsSettings":{"certificates":[{"certificateFile":%q,"keyFile":%q}]}}`, certPath, keyPath)
	config := &xray.Config{
		InboundConfigs: []xray.InboundConfig{{
			Tag:            "inbound-tls",
			Port:           443,
			StreamSettings: json_util.RawMessage(stream),
		}},
	}
	if err := validateInboundCerts(config); err != nil {
		t.Fatalf("readable certificates should validate: %v", err)
	}
}

func TestValidateInboundCertsIgnoresInboundsWithoutTLSFiles(t *testing.T) {
	config := &xray.Config{
		InboundConfigs: []xray.InboundConfig{{
			Tag:            "inbound-plain",
			Port:           8080,
			StreamSettings: json_util.RawMessage(`{"network":"tcp"}`),
		}},
	}
	if err := validateInboundCerts(config); err != nil {
		t.Fatalf("a plain inbound references no files: %v", err)
	}
}

func TestValidateInboundCertsRejectsEmptyFile(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(certPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	stream := fmt.Sprintf(`{"security":"tls","tlsSettings":{"certificates":[{"certificateFile":%q}]}}`, certPath)
	config := &xray.Config{
		InboundConfigs: []xray.InboundConfig{{
			Tag:            "inbound-tls",
			Port:           443,
			StreamSettings: json_util.RawMessage(stream),
		}},
	}
	err := validateInboundCerts(config)
	if err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("an empty certificate file should be rejected, got: %v", err)
	}
}

func TestValidateInboundCertsIgnoresStaleTLSSettingsWhenSecurityIsNotTLS(t *testing.T) {
	// A panel that switched an inbound from TLS to REALITY keeps the old
	// tlsSettings around. Xray never reads those files, so a stale path there
	// must not stop the whole configuration from starting.
	config := &xray.Config{
		InboundConfigs: []xray.InboundConfig{{
			Tag:            "inbound-reality",
			Port:           8443,
			StreamSettings: json_util.RawMessage(`{"security":"reality","tlsSettings":{"certificates":[{"certificateFile":"/gone/stale.pem"}]},"realitySettings":{}}`),
		}},
	}
	if err := validateInboundCerts(config); err != nil {
		t.Fatalf("stale tlsSettings on a non-TLS inbound must be ignored: %v", err)
	}
}
