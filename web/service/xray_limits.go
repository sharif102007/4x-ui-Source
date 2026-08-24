package service

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"os/exec"
	"sort"
	"strings"
	"sync"

	"github.com/sharif102007/4x-ui/v2/logger"
	"github.com/sharif102007/4x-ui/v2/util/json_util"
	"github.com/sharif102007/4x-ui/v2/xray"
)

const (
	xrayNftTable = "fourxui_xray"
	xrayLimitTag = "4xui-speed-"
)

type xrayBandwidthLimit struct {
	Email        string
	DownloadMbps int
	UploadMbps   int
	Mark         int
}

var (
	xrayPolicyMu        sync.Mutex
	xrayPolicySignature string

	xrayLimitStatusMu  sync.RWMutex
	xrayLimitLastError string
	xrayLimitApplied   int
)

// recordXrayLimitStatus stores the outcome of the most recent attempt to apply
// per-client speed limits. Previously a failure was only a log line, so the UI
// kept showing the limit switch as on while nothing was actually enforced.
func recordXrayLimitStatus(applied int, err error) {
	xrayLimitStatusMu.Lock()
	defer xrayLimitStatusMu.Unlock()
	xrayLimitApplied = applied
	if err != nil {
		xrayLimitLastError = err.Error()
		return
	}
	xrayLimitLastError = ""
}

// XrayLimitStatus reports how many clients currently have an enforced speed
// limit, and the error from the last failed apply if there was one.
func XrayLimitStatus() (int, string) {
	xrayLimitStatusMu.RLock()
	defer xrayLimitStatusMu.RUnlock()
	return xrayLimitApplied, xrayLimitLastError
}

func numberAsInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	case string:
		// Older panel builds sometimes persisted numeric form values as
		// strings. Accept them so a migrated client is not silently unlimited.
		var i int
		if _, err := fmt.Sscanf(strings.TrimSpace(n), "%d", &i); err == nil {
			return i
		}
	default:
		return 0
	}
	return 0
}

func collectXrayBandwidthLimit(client map[string]any) (xrayBandwidthLimit, bool) {
	email, _ := client["email"].(string)
	enabled, _ := client["speedLimit"].(bool)
	down := numberAsInt(client["downloadMbps"])
	up := numberAsInt(client["uploadMbps"])
	if !enabled || email == "" || (down <= 0 && up <= 0) {
		return xrayBandwidthLimit{}, false
	}
	if down < 0 || up < 0 || down > 100000 || up > 100000 {
		logger.Warningf("xray speed limit ignored for %s: invalid rate", email)
		return xrayBandwidthLimit{}, false
	}
	return xrayBandwidthLimit{Email: email, DownloadMbps: down, UploadMbps: up}, true
}

func assignXrayMarks(limits []xrayBandwidthLimit) {
	sort.Slice(limits, func(i, j int) bool { return limits[i].Email < limits[j].Email })
	used := make(map[int]struct{}, len(limits))
	for i := range limits {
		h := fnv.New32a()
		_, _ = h.Write([]byte(limits[i].Email))
		mark := 0x200000 | int(h.Sum32()&0x0fffff)
		for {
			if _, exists := used[mark]; !exists {
				break
			}
			mark++
		}
		used[mark] = struct{}{}
		limits[i].Mark = mark
	}
}

func injectXrayBandwidthConfig(config *xray.Config, limits []xrayBandwidthLimit) error {
	assignXrayMarks(limits)

	var outbounds []map[string]any
	if len(config.OutboundConfigs) > 0 {
		if err := json.Unmarshal(config.OutboundConfigs, &outbounds); err != nil {
			return fmt.Errorf("parse Xray outbounds for speed limits: %w", err)
		}
	}
	filteredOutbounds := outbounds[:0]
	for _, outbound := range outbounds {
		tag, _ := outbound["tag"].(string)
		if !strings.HasPrefix(tag, xrayLimitTag) {
			filteredOutbounds = append(filteredOutbounds, outbound)
		}
	}
	outbounds = filteredOutbounds
	baseOutbound := map[string]any{"protocol": "freedom", "settings": map[string]any{}}
	// The direct freedom outbound is the only safe base for a marked per-client
	// egress path. Custom configs may put a block/proxy outbound first, so we
	// only clone an existing outbound when it really is freedom. Falling back to
	// outbounds[0] (the previous behaviour) cloned whatever came first: if that
	// was blackhole, every rate-limited client had all traffic dropped instead
	// of shaped, which reads as "the client is broken" rather than "limited".
	baseIndex := -1
	for i, candidate := range outbounds {
		if protocol, _ := candidate["protocol"].(string); protocol == "freedom" {
			baseIndex = i
			break
		}
	}
	if baseIndex >= 0 {
		baseJSON, err := json.Marshal(outbounds[baseIndex])
		if err != nil {
			return err
		}
		if err := json.Unmarshal(baseJSON, &baseOutbound); err != nil {
			return err
		}
	} else if len(outbounds) > 0 {
		logger.Warning("xray: no freedom outbound in template; speed-limited clients will use a synthesized direct outbound")
	}
	// A cloned outbound must never keep the original's tag or the config will
	// have duplicate tags and Xray will refuse to start.
	delete(baseOutbound, "tag")

	var routing map[string]any
	if len(config.RouterConfig) > 0 {
		if err := json.Unmarshal(config.RouterConfig, &routing); err != nil {
			return fmt.Errorf("parse Xray routing for speed limits: %w", err)
		}
	}
	if routing == nil {
		routing = map[string]any{}
	}
	// Any tag that terminates traffic (blackhole outbound, or the conventional
	// "block"/"blocked" tag name) must keep its precedence over the speed rules.
	// The speed rule matches on `user` alone, so if it were placed first - as it
	// was previously - a rate-limited client bypassed every ad/malware/private-IP
	// block rule the operator had configured. Ordering is therefore:
	//   1. block rules   (still enforced for limited clients)
	//   2. speed rules   (mark the client's traffic)
	//   3. everything else
	// Consequence, documented rather than hidden: a limited client no longer
	// follows custom rules that route specific traffic to a *different* proxy
	// outbound, because a connection can only leave through one outbound and the
	// marked one is what carries the shaping mark.
	blockTags := map[string]struct{}{"block": {}, "blocked": {}}
	for _, outbound := range outbounds {
		if protocol, _ := outbound["protocol"].(string); protocol == "blackhole" {
			if tag, _ := outbound["tag"].(string); tag != "" {
				blockTags[tag] = struct{}{}
			}
		}
	}

	// First remove generated rules while preserving the operator's exact order.
	// This matters when no limits are enabled: the stock API rule must remain
	// ahead of the private-IP block rule or Xray's loopback API is blackholed.
	var cleanRules []any
	if rules, ok := routing["rules"].([]any); ok {
		for _, raw := range rules {
			rule, _ := raw.(map[string]any)
			outboundTag, _ := rule["outboundTag"].(string)
			if strings.HasPrefix(outboundTag, xrayLimitTag) {
				// Stale rule from a previous generation of this config.
				continue
			}
			cleanRules = append(cleanRules, raw)
		}
	}

	var infrastructureRules []any
	var blockingRules []any
	var existingRules []any
	if len(limits) == 0 {
		existingRules = cleanRules
	} else {
		for _, raw := range cleanRules {
			rule, _ := raw.(map[string]any)
			outboundTag, _ := rule["outboundTag"].(string)
			// Xray's internal API route is infrastructure, not ordinary user
			// traffic. It must always win before geoip:private blackholes.
			if outboundTag == "api" {
				infrastructureRules = append(infrastructureRules, raw)
				continue
			}
			if _, isBlock := blockTags[outboundTag]; isBlock {
				blockingRules = append(blockingRules, raw)
				continue
			}
			existingRules = append(existingRules, raw)
		}
	}

	limitRules := make([]any, 0, len(limits))
	for _, limit := range limits {
		tag := fmt.Sprintf("%s%x", xrayLimitTag, limit.Mark)
		baseJSON, err := json.Marshal(baseOutbound)
		if err != nil {
			return err
		}
		limitedOutbound := make(map[string]any)
		if err := json.Unmarshal(baseJSON, &limitedOutbound); err != nil {
			return err
		}
		limitedOutbound["tag"] = tag
		streamSettings, _ := limitedOutbound["streamSettings"].(map[string]any)
		if streamSettings == nil {
			streamSettings = map[string]any{}
		}
		sockopt, _ := streamSettings["sockopt"].(map[string]any)
		if sockopt == nil {
			sockopt = map[string]any{}
		}
		sockopt["mark"] = limit.Mark
		streamSettings["sockopt"] = sockopt
		limitedOutbound["streamSettings"] = streamSettings
		outbounds = append(outbounds, limitedOutbound)
		limitRules = append(limitRules, map[string]any{
			"type":        "field",
			"user":        []string{limit.Email},
			"outboundTag": tag,
		})
	}
	orderedRules := make([]any, 0, len(infrastructureRules)+len(blockingRules)+len(limitRules)+len(existingRules))
	orderedRules = append(orderedRules, infrastructureRules...)
	orderedRules = append(orderedRules, blockingRules...)
	orderedRules = append(orderedRules, limitRules...)
	orderedRules = append(orderedRules, existingRules...)
	routing["rules"] = orderedRules
	outboundJSON, err := json.Marshal(outbounds)
	if err != nil {
		return err
	}
	routingJSON, err := json.Marshal(routing)
	if err != nil {
		return err
	}
	config.OutboundConfigs = json_util.RawMessage(outboundJSON)
	config.RouterConfig = json_util.RawMessage(routingJSON)
	return nil
}

func addXrayBandwidthConfig(config *xray.Config, limits []xrayBandwidthLimit) error {
	if err := injectXrayBandwidthConfig(config, limits); err != nil {
		return err
	}
	return applyXraySpeedPolicy(limits)
}

func buildXrayPolicy(limits []xrayBandwidthLimit) (string, string) {
	var declarations, outputRules, inputRules, signature strings.Builder
	inputRules.WriteString("    ct mark != 0 meta mark set ct mark\n")
	if len(limits) > 0 {
		// One socket-mark restore is enough for the whole chain. Keeping this
		// inside the client loop made every packet evaluate the same expression
		// once per limited client. Xray sets SO_MARK on its outbound socket;
		// this copies that value into the packet mark used below.
		outputRules.WriteString("    socket mark != 0 meta mark set socket mark\n")
	}
	for _, limit := range limits {
		fmt.Fprintf(&signature, "%s:%d:%d:%d;", limit.Email, limit.Mark, limit.DownloadMbps, limit.UploadMbps)
		upCounter := fmt.Sprintf("xray_%x_up", limit.Mark)
		downCounter := fmt.Sprintf("xray_%x_down", limit.Mark)
		fmt.Fprintf(&declarations, "  counter %s {}\n  counter %s {}\n", upCounter, downCounter)
		fmt.Fprintf(&outputRules, "    meta mark %d ct mark set meta mark counter name %s\n", limit.Mark, upCounter)
		if limit.UploadMbps > 0 {
			outputRules.WriteString(nftRateRule(limit.Mark, limit.UploadMbps, ""))
		}
		if limit.DownloadMbps > 0 {
			inputRules.WriteString(nftRateRule(limit.Mark, limit.DownloadMbps, ""))
		}
		fmt.Fprintf(&inputRules, "    meta mark %d counter name %s\n", limit.Mark, downCounter)
	}
	sig := fmt.Sprintf("%x", sha256.Sum256([]byte(signature.String())))
	script := fmt.Sprintf("table inet %s {\n%s  chain output {\n    type filter hook output priority mangle; policy accept;\n%s  }\n  chain prerouting {\n    type filter hook prerouting priority mangle; policy accept;\n%s  }\n}\n", xrayNftTable, declarations.String(), outputRules.String(), inputRules.String())
	return sig, script
}

func applyXraySpeedPolicy(limits []xrayBandwidthLimit) error {
	xrayPolicyMu.Lock()
	defer xrayPolicyMu.Unlock()
	if len(limits) == 0 {
		if xrayPolicySignature != "" {
			_ = exec.Command("nft", "delete", "table", "inet", xrayNftTable).Run()
			xrayPolicySignature = ""
		}
		setXraySpeedLimitPresence(false)
		return nil
	}
	sig, script := buildXrayPolicy(limits)
	if sig == xrayPolicySignature {
		// A firewall reload can remove the table while the panel process is
		// still alive. Verify it exists before trusting the in-memory cache.
		if err := exec.Command("nft", "list", "table", "inet", xrayNftTable).Run(); err == nil {
			return nil
		}
	}
	if err := applyNftTable(xrayNftTable, script); err != nil {
		// socket expressions are available on current nftables, but some
		// older VPS images ship a parser without them. Keep a compatible
		// fallback; the kernel normally propagates SO_MARK to skb->mark.
		legacyScript := strings.ReplaceAll(script, "    socket mark != 0 meta mark set socket mark\n", "")
		if legacyScript == script {
			return fmt.Errorf("apply Xray client speed policy: %w", err)
		}
		if legacyErr := applyNftTable(xrayNftTable, legacyScript); legacyErr != nil {
			return fmt.Errorf("apply Xray client speed policy: %w (legacy fallback: %v)", err, legacyErr)
		}
		logger.Warning("xray: nftables socket-mark expression unavailable; using kernel mark propagation fallback")
	}
	xrayPolicySignature = sig
	logger.Infof("xray: applied speed policy for %d clients", len(limits))
	setXraySpeedLimitPresence(true)
	return nil
}
