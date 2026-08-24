package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/sharif102007/4x-ui/v2/xray"
)

// certRef is a single certificate or key file referenced by an inbound's TLS
// settings.
type certRef struct {
	Tag  string
	Port int
	Kind string // "certificateFile" or "keyFile"
	Path string
}

// collectInboundCertRefs walks every inbound's streamSettings and returns each
// on-disk certificate and key file it references. Inline `certificate` /
// `key` byte arrays and REALITY inbounds reference no files and are skipped.
func collectInboundCertRefs(config *xray.Config) []certRef {
	if config == nil {
		return nil
	}
	refs := make([]certRef, 0)
	for i := range config.InboundConfigs {
		inbound := &config.InboundConfigs[i]
		if len(inbound.StreamSettings) == 0 {
			continue
		}
		var stream map[string]any
		if err := json.Unmarshal(inbound.StreamSettings, &stream); err != nil {
			// A malformed streamSettings is Xray's problem to report; this
			// function only looks for file references.
			continue
		}
		// Only inbounds whose transport security is actually "tls" load these
		// files. Panels routinely carry leftover tlsSettings on an inbound that
		// was switched to reality or to no security at all - Xray ignores them
		// completely, so treating a stale path there as fatal would refuse to
		// start a configuration that works perfectly well.
		if security, _ := stream["security"].(string); !strings.EqualFold(security, "tls") {
			continue
		}
		tlsSettings, ok := stream["tlsSettings"].(map[string]any)
		if !ok {
			continue
		}
		certificates, ok := tlsSettings["certificates"].([]any)
		if !ok {
			continue
		}
		for _, raw := range certificates {
			certificate, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			for _, key := range []string{"certificateFile", "keyFile"} {
				path, _ := certificate[key].(string)
				path = strings.TrimSpace(path)
				if path == "" {
					continue
				}
				refs = append(refs, certRef{
					Tag:  inbound.Tag,
					Port: inbound.Port,
					Kind: key,
					Path: path,
				})
			}
		}
	}
	return refs
}

// validateInboundCerts reports every referenced certificate file that is missing
// or unreadable.
//
// Xray exits immediately when a TLS inbound points at a file that is not there.
// The health-check job then sees a crashed process and restarts it, which fails
// for the same reason, forever - the only trace being a repeated
// "no such file or directory" in the log. Checking up front turns that loop into
// one message that names the inbound and the exact path.
func validateInboundCerts(config *xray.Config) error {
	refs := collectInboundCertRefs(config)
	if len(refs) == 0 {
		return nil
	}

	problems := make([]string, 0)
	seen := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		if _, dup := seen[ref.Path]; dup {
			continue
		}
		seen[ref.Path] = struct{}{}

		info, err := os.Stat(ref.Path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			problems = append(problems, fmt.Sprintf(
				"inbound %q (port %d): %s %s does not exist",
				ref.Tag, ref.Port, ref.Kind, ref.Path))
			continue
		case err != nil:
			problems = append(problems, fmt.Sprintf(
				"inbound %q (port %d): %s %s is not readable: %v",
				ref.Tag, ref.Port, ref.Kind, ref.Path, err))
			continue
		case info.IsDir():
			problems = append(problems, fmt.Sprintf(
				"inbound %q (port %d): %s %s is a directory, not a file",
				ref.Tag, ref.Port, ref.Kind, ref.Path))
			continue
		case info.Size() == 0:
			problems = append(problems, fmt.Sprintf(
				"inbound %q (port %d): %s %s is empty",
				ref.Tag, ref.Port, ref.Kind, ref.Path))
			continue
		}

		// Stat succeeding does not mean the panel can read the file: a
		// certificate under another user's home directory is the common case.
		file, err := os.Open(ref.Path)
		if err != nil {
			problems = append(problems, fmt.Sprintf(
				"inbound %q (port %d): %s %s cannot be opened: %v",
				ref.Tag, ref.Port, ref.Kind, ref.Path, err))
			continue
		}
		_ = file.Close()
	}

	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	// Point at the fix rather than only the fault. Certificates under
	// /root/cert/<domain>/ are the panel's own layout, so `x-ui ssl fix` can
	// re-issue every missing one without the operator working out the domain,
	// the challenge method or which service is holding port 80.
	return fmt.Errorf("TLS certificate problems prevent Xray from starting "+
		"(run 'x-ui ssl fix' to re-issue the missing certificates, "+
		"or disable the affected inbound to let Xray start without it):\n  %s",
		strings.Join(problems, "\n  "))
}
