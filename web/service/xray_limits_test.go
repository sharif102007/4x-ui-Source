package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/sharif102007/4x-ui/v2/util/json_util"
	"github.com/sharif102007/4x-ui/v2/xray"
)

func TestCollectXrayBandwidthLimit(t *testing.T) {
	limit, ok := collectXrayBandwidthLimit(map[string]any{
		"email":        "client@example.com",
		"speedLimit":   true,
		"downloadMbps": float64(8),
		"uploadMbps":   float64(3),
	})
	if !ok || limit.Email != "client@example.com" || limit.DownloadMbps != 8 || limit.UploadMbps != 3 {
		t.Fatalf("unexpected limit: %#v, ok=%v", limit, ok)
	}
}

func TestXraySpeedConfigAddsMarkedOutboundAndUserRule(t *testing.T) {
	config := &xray.Config{
		OutboundConfigs: json_util.RawMessage(`[{"tag":"direct","protocol":"freedom","settings":{}}]`),
		RouterConfig:    json_util.RawMessage(`{"domainStrategy":"AsIs","rules":[]}`),
	}
	limits := []xrayBandwidthLimit{{Email: "limited", DownloadMbps: 2, UploadMbps: 1}}
	if err := injectXrayBandwidthConfig(config, limits); err != nil {
		t.Fatal(err)
	}
	var outbounds []map[string]any
	if err := json.Unmarshal(config.OutboundConfigs, &outbounds); err != nil {
		t.Fatal(err)
	}
	if len(outbounds) != 2 {
		t.Fatalf("expected original and limited outbound, got %d", len(outbounds))
	}
	mark := limits[0].Mark
	if mark == 0 {
		t.Fatal("mark was not assigned")
	}
	wantTag := fmt.Sprintf("%s%x", xrayLimitTag, mark)
	if outbounds[1]["tag"] != wantTag {
		t.Fatalf("unexpected limited outbound tag: %v", outbounds[1]["tag"])
	}
	var routing map[string]any
	if err := json.Unmarshal(config.RouterConfig, &routing); err != nil {
		t.Fatal(err)
	}
	rules := routing["rules"].([]any)
	first := rules[0].(map[string]any)
	if first["outboundTag"] != wantTag {
		t.Fatalf("user rule does not target limited outbound: %#v", first)
	}
	_, script := buildXrayPolicy(limits)
	if !strings.Contains(script, "socket mark != 0 meta mark set socket mark") ||
		!strings.Contains(script, "meta mark ") ||
		!strings.Contains(script, "250000 bytes/second") ||
		!strings.Contains(script, "125000 bytes/second") {
		t.Fatalf("unexpected nft policy:\n%s", script)
	}
}

func TestXrayNoLimitPreservesStockRoutingOrder(t *testing.T) {
	config := &xray.Config{
		OutboundConfigs: json_util.RawMessage(`[{"tag":"direct","protocol":"freedom","settings":{}},{"tag":"blocked","protocol":"blackhole","settings":{}}]`),
		RouterConfig:    json_util.RawMessage(`{"rules":[{"type":"field","inboundTag":["api"],"outboundTag":"api"},{"type":"field","outboundTag":"blocked","ip":["geoip:private"]},{"type":"field","outboundTag":"blocked","protocol":["bittorrent"]}]}`),
	}
	if err := injectXrayBandwidthConfig(config, nil); err != nil {
		t.Fatal(err)
	}
	var routing map[string]any
	if err := json.Unmarshal(config.RouterConfig, &routing); err != nil {
		t.Fatal(err)
	}
	rules := routing["rules"].([]any)
	want := []string{"api", "blocked", "blocked"}
	for i, tag := range want {
		got := rules[i].(map[string]any)["outboundTag"]
		if got != tag {
			t.Fatalf("routing order changed at %d: got %v, want %s", i, got, tag)
		}
	}
}

func TestXrayApiRuleStaysBeforeBlocksAndLimits(t *testing.T) {
	config := &xray.Config{
		OutboundConfigs: json_util.RawMessage(`[{"tag":"direct","protocol":"freedom","settings":{}},{"tag":"blocked","protocol":"blackhole","settings":{}}]`),
		RouterConfig:    json_util.RawMessage(`{"rules":[{"type":"field","inboundTag":["api"],"outboundTag":"api"},{"type":"field","outboundTag":"blocked","ip":["geoip:private"]}]}`),
	}
	limits := []xrayBandwidthLimit{{Email: "one", DownloadMbps: 2}, {Email: "two", UploadMbps: 1}}
	if err := injectXrayBandwidthConfig(config, limits); err != nil {
		t.Fatal(err)
	}
	var routing map[string]any
	if err := json.Unmarshal(config.RouterConfig, &routing); err != nil {
		t.Fatal(err)
	}
	rules := routing["rules"].([]any)
	if got := rules[0].(map[string]any)["outboundTag"]; got != "api" {
		t.Fatalf("API route lost first priority: %v", got)
	}
	if got := rules[1].(map[string]any)["outboundTag"]; got != "blocked" {
		t.Fatalf("block route should follow API infrastructure: %v", got)
	}
	_, script := buildXrayPolicy(limits)
	if got := strings.Count(script, "socket mark != 0 meta mark set socket mark"); got != 1 {
		t.Fatalf("socket mark restore duplicated %d times", got)
	}
}

func TestCollectXrayBandwidthLimitAcceptsPersistedStrings(t *testing.T) {
	limit, ok := collectXrayBandwidthLimit(map[string]any{
		"email":        "legacy@example.com",
		"speedLimit":   true,
		"downloadMbps": "8",
		"uploadMbps":   "3",
	})
	if !ok || limit.DownloadMbps != 8 || limit.UploadMbps != 3 {
		t.Fatalf("string rates were not parsed: %#v, ok=%v", limit, ok)
	}
}

func TestRateConversionUsesMegabits(t *testing.T) {
	if got := rateBytesPerSecond(2); got != 250000 {
		t.Fatalf("2 Mbps = 250000 bytes/s, got %d", got)
	}
}

func TestXraySpeedRulesDoNotOvertakeBlockRules(t *testing.T) {
	config := &xray.Config{
		OutboundConfigs: json_util.RawMessage(`[{"tag":"direct","protocol":"freedom","settings":{}},{"tag":"blocked","protocol":"blackhole","settings":{}}]`),
		RouterConfig:    json_util.RawMessage(`{"rules":[{"type":"field","outboundTag":"blocked","domain":["geosite:category-ads-all"]},{"type":"field","outboundTag":"direct","network":"tcp,udp"}]}`),
	}
	limits := []xrayBandwidthLimit{{Email: "limited", DownloadMbps: 2, UploadMbps: 1}}
	if err := injectXrayBandwidthConfig(config, limits); err != nil {
		t.Fatal(err)
	}
	var routing map[string]any
	if err := json.Unmarshal(config.RouterConfig, &routing); err != nil {
		t.Fatal(err)
	}
	rules, ok := routing["rules"].([]any)
	if !ok || len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %#v", routing["rules"])
	}
	first, _ := rules[0].(map[string]any)
	if first["outboundTag"] != "blocked" {
		t.Fatalf("block rule lost precedence, first rule is %#v", first)
	}
	second, _ := rules[1].(map[string]any)
	wantTag := fmt.Sprintf("%s%x", xrayLimitTag, limits[0].Mark)
	if second["outboundTag"] != wantTag {
		t.Fatalf("speed rule should follow block rules, got %#v", second)
	}
	third, _ := rules[2].(map[string]any)
	if third["outboundTag"] != "direct" {
		t.Fatalf("general rule should come last, got %#v", third)
	}
}

func TestXraySpeedBaseOutboundNeverClonesBlackhole(t *testing.T) {
	config := &xray.Config{
		OutboundConfigs: json_util.RawMessage(`[{"tag":"blocked","protocol":"blackhole","settings":{}}]`),
		RouterConfig:    json_util.RawMessage(`{"rules":[]}`),
	}
	limits := []xrayBandwidthLimit{{Email: "limited", DownloadMbps: 5}}
	if err := injectXrayBandwidthConfig(config, limits); err != nil {
		t.Fatal(err)
	}
	var outbounds []map[string]any
	if err := json.Unmarshal(config.OutboundConfigs, &outbounds); err != nil {
		t.Fatal(err)
	}
	if len(outbounds) != 2 {
		t.Fatalf("expected original and limited outbound, got %d", len(outbounds))
	}
	limited := outbounds[1]
	if limited["protocol"] != "freedom" {
		t.Fatalf("limited client traffic would be blackholed: %#v", limited)
	}
	if limited["tag"] == "blocked" {
		t.Fatal("limited outbound reused the original tag")
	}
}

func TestXrayLimitStatusRecordsFailure(t *testing.T) {
	recordXrayLimitStatus(0, errors.New("nft missing"))
	if applied, msg := XrayLimitStatus(); applied != 0 || msg != "nft missing" {
		t.Fatalf("failure not recorded: applied=%d msg=%q", applied, msg)
	}
	recordXrayLimitStatus(3, nil)
	if applied, msg := XrayLimitStatus(); applied != 3 || msg != "" {
		t.Fatalf("success not recorded: applied=%d msg=%q", applied, msg)
	}
}
