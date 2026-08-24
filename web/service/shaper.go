package service

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/sharif102007/4x-ui/v2/logger"
)

// Automatic queue-based shaping.
//
// The nftables policy the panel installs is a *policer*: traffic above the
// configured rate is dropped. For TCP that reads as a much lower effective
// speed than the number in the UI, because every drop triggers congestion
// backoff - which is exactly the "the speed limit does not work" symptom.
// 4xui-shaper.sh turns the same marks into real HTB queues (upload on the WAN
// egress, download via an IFB device), which shapes instead of dropping.
//
// The script existed but had to be invoked by hand, so in practice it was never
// on. This wires it to the panel's own policy lifecycle: it goes on the first
// time any client has a speed limit and comes off when the last one is removed.
//
// Safety properties inherited from the script itself, not re-implemented here:
//   - unlimited download traffic stays off IFB entirely;
//   - WAN HTB is installed only when at least one upload limit exists, and its
//     default class keeps unclassified upload traffic at full link speed;
//   - `apply` verifies the default gateway still answers afterwards and rolls
//     itself back if not;
//   - `rollback` is safe to run when nothing is installed.
//
// Every failure here is logged and swallowed. Shaping is an enhancement over
// the policer, and the policer is already active by the time this runs - a host
// without htb/ifb/act_connmark must keep working exactly as it did before.

const (
	shaperScriptName = "4xui-shaper.sh"
	shaperTimeout    = 90 * time.Second
)

var (
	shaperMu       sync.Mutex
	shaperApplied  bool
	shaperUnusable bool
)

// shaperScriptPath locates the script next to the running binary. Returns ""
// when it is not installed (source checkouts, containers built without it).
func shaperScriptPath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	p := filepath.Join(filepath.Dir(exe), shaperScriptName)
	info, err := os.Stat(p)
	if err != nil || info.IsDir() {
		return ""
	}
	return p
}

func runShaper(script, action string) error {
	cmd := exec.Command("bash", script, action)
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(shaperTimeout):
		_ = cmd.Process.Kill()
		<-done
		return os.ErrDeadlineExceeded
	}
}

// syncTrafficShaper brings queue shaping in line with the current speed-limit
// policy. An active shaper is deliberately rebuilt when a policy changes so
// edited rates do not leave stale HTB classes behind.
func syncTrafficShaper(wanted bool) {
	shaperMu.Lock()
	defer shaperMu.Unlock()

	if !wanted && !shaperApplied {
		return
	}

	script := shaperScriptPath()
	if script == "" {
		return
	}

	if wanted {
		if shaperUnusable {
			return
		}
		// `check` is cheap and non-mutating; it tells us whether the kernel has
		// htb, ifb and act_connmark before we touch the live qdisc tree.
		if err := runShaper(script, "check"); err != nil {
			// Latch it: probing once per policy change on a host that will
			// never support it is pure noise.
			shaperUnusable = true
			logger.Warningf("shaper: host cannot support queue shaping, staying on the nftables policer (%v)", err)
			return
		}
		if err := runShaper(script, "apply"); err != nil {
			logger.Warningf("shaper: apply failed, staying on the nftables policer: %v", err)
			return
		}
		shaperApplied = true
		logger.Info("shaper: queue-based traffic shaping active")
		return
	}

	if !shaperApplied {
		return
	}
	if err := runShaper(script, "rollback"); err != nil {
		logger.Warningf("shaper: rollback failed: %v", err)
		return
	}
	shaperApplied = false
	logger.Info("shaper: queue-based traffic shaping removed (no speed limits configured)")
}

// speedLimitState tracks whether either subsystem currently has limits, so the
// shaper is only removed once *both* are clear.
var (
	speedStateMu sync.Mutex
	xrayHasLimit bool
	sshHasLimit  bool

	// Reconciliation runs on one long-lived worker rather than inline.
	// Callers hold the Xray/SSH policy mutex, and `tc` work can take seconds -
	// blocking there would stall Xray config regeneration. The channel holds a
	// single slot and sends are non-blocking, so bursts collapse to "reconcile
	// once more with the latest desired state" and no goroutine ever piles up.
	shaperWorkerOnce sync.Once
	shaperRequests   = make(chan bool, 1)
)

func startShaperWorker() {
	shaperWorkerOnce.Do(func() {
		go func() {
			for wanted := range shaperRequests {
				syncTrafficShaper(wanted)
			}
		}()
	})
}

func requestShaperState(wanted bool) {
	startShaperWorker()
	select {
	case shaperRequests <- wanted:
	default:
		// A reconciliation is already queued; it will read the state below.
		select {
		case <-shaperRequests:
		default:
		}
		select {
		case shaperRequests <- wanted:
		default:
		}
	}
}

func setXraySpeedLimitPresence(present bool) {
	speedStateMu.Lock()
	xrayHasLimit = present
	anyLimit := xrayHasLimit || sshHasLimit
	speedStateMu.Unlock()
	requestShaperState(anyLimit)
}

func setSshSpeedLimitPresence(present bool) {
	speedStateMu.Lock()
	sshHasLimit = present
	anyLimit := xrayHasLimit || sshHasLimit
	speedStateMu.Unlock()
	requestShaperState(anyLimit)
}
