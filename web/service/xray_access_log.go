package service

import (
	"encoding/json"
	"path/filepath"

	"github.com/sharif102007/4x-ui/v2/config"
	"github.com/sharif102007/4x-ui/v2/logger"
)

// Xray access log auto-enable.
//
// The per-client IP limit is implemented by parsing Xray's access log
// (check_client_ip_job). If `log.access` is unset in the Xray template - which
// is the default - that job finds nothing to read and silently enforces
// nothing: the operator sets "IP limit: 2" in the UI, sees no error, and gets
// no limiting. The only signal was a warning buried in the panel log telling
// them to configure it by hand.
//
// This turns it on once, at startup, when it is not already configured.
//
// Only ever fills in a *missing* value: an operator who deliberately set
// "none", or who points the log somewhere specific, is left alone. Log growth
// is already handled by clear_logs_job.
func EnsureXrayAccessLog() {
	settingService := SettingService{}

	template, err := settingService.GetXrayConfigTemplate()
	if err != nil || template == "" {
		logger.Debug("access log: no Xray template available, skipping")
		return
	}

	var cfg map[string]any
	if err := json.Unmarshal([]byte(template), &cfg); err != nil {
		logger.Warningf("access log: cannot parse Xray template, leaving it alone: %v", err)
		return
	}

	logSection, _ := cfg["log"].(map[string]any)
	if logSection == nil {
		logSection = map[string]any{}
	}

	// Respect an explicit choice, including an explicit "none".
	if existing, ok := logSection["access"].(string); ok && existing != "" {
		return
	}

	accessLogPath := filepath.Join(config.GetLogFolder(), "access.log")
	logSection["access"] = accessLogPath
	if _, ok := logSection["loglevel"]; !ok {
		logSection["loglevel"] = "warning"
	}
	cfg["log"] = logSection

	updated, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		logger.Warningf("access log: cannot serialise Xray template: %v", err)
		return
	}
	if err := settingService.setString("xrayTemplateConfig", string(updated)); err != nil {
		logger.Warningf("access log: cannot save Xray template: %v", err)
		return
	}
	logger.Infof("access log: enabled at %s so per-client IP limits can be enforced", accessLogPath)
}
