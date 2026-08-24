package model

import "testing"

func TestIsHysteria(t *testing.T) {
	cases := []struct {
		in   Protocol
		want bool
	}{
		{Hysteria, true},
		{Hysteria2, true},
		{VLESS, false},
		{Shadowsocks, false},
		{Protocol(""), false},
		{Protocol("hysteria3"), false},
	}
	for _, c := range cases {
		if got := IsHysteria(c.in); got != c.want {
			t.Errorf("IsHysteria(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestGenXrayInboundConfigPayloadBypassUsesLoopbackBackend(t *testing.T) {
	in := &Inbound{
		Listen:             "0.0.0.0",
		Port:               443,
		Protocol:           VLESS,
		Settings:           `{}`,
		StreamSettings:     `{"network":"ws"}`,
		Tag:                "inbound-443",
		Sniffing:           `{}`,
		PayloadBypass:      true,
		PayloadBackendPort: 32147,
	}
	cfg := in.GenXrayInboundConfig()
	if cfg.Port != 32147 {
		t.Fatalf("runtime Xray port = %d, want hidden backend 32147", cfg.Port)
	}
	if string(cfg.Listen) != `"127.0.0.1"` {
		t.Fatalf("runtime Xray listen = %s, want loopback", cfg.Listen)
	}
}

func TestGenXrayInboundConfigPayloadBypassOffKeepsPublicPort(t *testing.T) {
	in := &Inbound{
		Listen:             "0.0.0.0",
		Port:               443,
		Protocol:           VLESS,
		Settings:           `{}`,
		StreamSettings:     `{"network":"ws"}`,
		Tag:                "inbound-443",
		Sniffing:           `{}`,
		PayloadBypass:      false,
		PayloadBackendPort: 32147,
	}
	cfg := in.GenXrayInboundConfig()
	if cfg.Port != 443 {
		t.Fatalf("runtime Xray port = %d, want public port 443", cfg.Port)
	}
	if string(cfg.Listen) != `"0.0.0.0"` {
		t.Fatalf("runtime Xray listen = %s, want public listen", cfg.Listen)
	}
}
