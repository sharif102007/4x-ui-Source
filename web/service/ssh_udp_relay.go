package service

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sharif102007/4x-ui/v2/logger"
)

// udpgwMTU is the largest UDP payload the relay will forward in one piece.
// Android tunnel clients normally use an MTU around 1500 bytes; 8192 leaves
// useful headroom without creating oversized buffers on small VPS instances.
//
// Override with XUI_UDPGW_MTU=<bytes> in /etc/default/x-ui. Set it to 0 to
// omit the flag and use the installed badvpn build's default.
const defaultUdpgwMTU = 8192

const (
	udpgwUnitTemplatePath = "/etc/systemd/system/xui-udpgw@.service"
	udpgwStatePath        = "/etc/x-ui/ssh-manager/udpgw-ports"
	udpgwSourceDir        = "/tmp/4x-ui-badvpn-src"
)

func udpgwMTU() int {
	raw := os.Getenv("XUI_UDPGW_MTU")
	if raw == "" {
		return defaultUdpgwMTU
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 {
		logger.Warningf("ssh-manager: ignoring invalid XUI_UDPGW_MTU=%q", raw)
		return defaultUdpgwMTU
	}
	return v
}

func badvpnBinary() (string, error) {
	if p, err := exec.LookPath("badvpn-udpgw"); err == nil {
		return p, nil
	}
	for _, p := range []string{"/usr/local/bin/badvpn-udpgw", "/usr/bin/badvpn-udpgw", "/usr/sbin/badvpn-udpgw"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", exec.ErrNotFound
}

// BadvpnInstalled reports whether badvpn-udpgw is available.
func BadvpnInstalled() bool {
	_, err := badvpnBinary()
	return err == nil
}

// runUdpSetup is intentionally separate from sshSystem.run. Package index
// refreshes, source downloads and compilation routinely exceed the general SSH
// helper's short command timeout, which made first-time UDPGW setup unreliable.
func runUdpSetup(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("%s timed out after %s", name, timeout)
	}
	return string(out), err
}

func toolExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func aptLockBusy(output string) bool {
	low := strings.ToLower(output)
	for _, needle := range []string{
		"could not get lock",
		"unable to acquire the dpkg frontend lock",
		"unable to lock the administration directory",
		"is another process using it",
		"dpkg frontend lock was locked",
	} {
		if strings.Contains(low, needle) {
			return true
		}
	}
	return false
}

// runDpkgConfigure repairs the common interrupted-dpkg state without deleting
// lock files or killing an active package manager. If apt/dpkg is legitimately
// busy (for example unattended-upgrades just started), wait briefly and retry.
func runDpkgConfigure() (string, error) {
	dpkg, err := exec.LookPath("dpkg")
	if err != nil {
		return "", nil
	}
	deadline := time.Now().Add(90 * time.Second)
	for {
		out, err := runUdpSetup(2*time.Minute, dpkg, "--configure", "-a")
		if err == nil {
			return out, nil
		}
		if !aptLockBusy(out) || time.Now().After(deadline) {
			return out, err
		}
		time.Sleep(2 * time.Second)
	}
}

// prepareAptForUdpGW makes Debian/Ubuntu package management self-healing for
// first-time UDP relay setup. A previous interrupted apt/dpkg operation is a
// VPS state issue, but users should not need to SSH in and manually run
// `dpkg --configure -a` before enabling UDP relay in the panel.
func prepareAptForUdpGW() error {
	apt, err := exec.LookPath("apt-get")
	if err != nil {
		return nil
	}

	dpkgOut, dpkgErr := runDpkgConfigure()
	// apt-get's lock timeout waits for a legitimate unattended-upgrades/apt
	// process. Never remove lock files: doing so can corrupt dpkg state.
	fixArgs := []string{"-o", "DPkg::Lock::Timeout=90", "-f", "install", "-y"}
	fixOut, fixErr := runUdpSetup(5*time.Minute, apt, fixArgs...)
	if fixErr != nil {
		return fmt.Errorf("automatic dpkg/apt recovery failed: %v: %s", fixErr, strings.TrimSpace(fixOut))
	}
	if dpkgErr != nil {
		// Broken dependencies may have been the reason dpkg could not configure
		// packages. After `apt-get -f install`, one final configure pass should
		// complete any pending maintainer scripts.
		if out, err := runDpkgConfigure(); err != nil {
			combined := strings.TrimSpace(out)
			if combined == "" {
				combined = strings.TrimSpace(dpkgOut)
			}
			return fmt.Errorf("automatic dpkg configure failed: %v: %s", err, combined)
		}
	}
	return nil
}

func tryInstallBadvpnPackage() bool {
	if apt, err := exec.LookPath("apt-get"); err == nil {
		// Fresh VPS images frequently have stale package indexes. Refresh only
		// when UDPGW is requested and missing, never on normal panel startup/save
		// after badvpn-udpgw has already been installed.
		_, _ = runUdpSetup(3*time.Minute, apt, "-o", "DPkg::Lock::Timeout=90", "update")
		if _, err := runUdpSetup(3*time.Minute, apt, "-o", "DPkg::Lock::Timeout=90", "install", "-y", "badvpn"); err == nil && BadvpnInstalled() {
			return true
		}
	}
	if pacman, err := exec.LookPath("pacman"); err == nil {
		if _, err := runUdpSetup(3*time.Minute, pacman, "-Sy", "--noconfirm", "badvpn"); err == nil && BadvpnInstalled() {
			return true
		}
	}
	return false
}

func installBadvpnBuildDeps() error {
	var cmd string
	var args []string
	switch {
	case toolExists("apt-get"):
		cmd = "apt-get"
		args = []string{"-o", "DPkg::Lock::Timeout=90", "install", "-y", "build-essential", "cmake", "git"}
	case toolExists("dnf"):
		cmd = "dnf"
		args = []string{"install", "-y", "gcc", "gcc-c++", "make", "cmake", "git"}
	case toolExists("yum"):
		cmd = "yum"
		args = []string{"install", "-y", "gcc", "gcc-c++", "make", "cmake", "git"}
	case toolExists("pacman"):
		cmd = "pacman"
		args = []string{"-Sy", "--needed", "--noconfirm", "base-devel", "cmake", "git"}
	case toolExists("zypper"):
		cmd = "zypper"
		args = []string{"--non-interactive", "install", "gcc", "gcc-c++", "make", "cmake", "git"}
	case toolExists("apk"):
		cmd = "apk"
		args = []string{"add", "build-base", "cmake", "git"}
	default:
		return fmt.Errorf("no supported package manager found for badvpn build dependencies")
	}
	if out, err := runUdpSetup(5*time.Minute, cmd, args...); err != nil {
		return fmt.Errorf("install badvpn build dependencies: %v: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// EnsureBadvpn makes UDPGW available on the VPS. It first uses a distro
// package when one exists; otherwise it builds only the UDPGW component from
// upstream source. Setup is idempotent and runs only when an enabled SSH
// inbound requests UDP relay.
func EnsureBadvpn() error {
	if BadvpnInstalled() {
		return nil
	}
	logger.Info("ssh-manager: UDP relay requested; setting up badvpn-udpgw automatically")
	if toolExists("apt-get") {
		logger.Info("ssh-manager: checking and repairing apt/dpkg state before UDPGW setup")
		if err := prepareAptForUdpGW(); err != nil {
			return err
		}
	}
	if tryInstallBadvpnPackage() {
		logger.Info("ssh-manager: badvpn-udpgw installed from distro package")
		return nil
	}
	if err := installBadvpnBuildDeps(); err != nil {
		return err
	}

	_, _ = runUdpSetup(30*time.Second, "rm", "-rf", udpgwSourceDir)
	if out, err := runUdpSetup(3*time.Minute, "git", "clone", "--depth=1", "https://github.com/ambrop72/badvpn.git", udpgwSourceDir); err != nil {
		return fmt.Errorf("clone badvpn source: %v: %s", err, strings.TrimSpace(out))
	}
	defer func() { _, _ = runUdpSetup(30*time.Second, "rm", "-rf", udpgwSourceDir) }()

	buildDir := filepath.Join(udpgwSourceDir, "build")
	cmakeArgs := []string{
		"-S", udpgwSourceDir,
		"-B", buildDir,
		"-DBUILD_NOTHING_BY_DEFAULT=1",
		"-DBUILD_UDPGW=1",
		// New CMake versions can reject this archived project's old minimum
		// policy unless an explicit compatible policy floor is supplied.
		"-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
	}
	if out, err := runUdpSetup(3*time.Minute, "cmake", cmakeArgs...); err != nil {
		return fmt.Errorf("configure badvpn udpgw: %v: %s", err, strings.TrimSpace(out))
	}
	// UDPGW is small. Keep parallelism conservative so setup also succeeds on
	// low-memory VPS plans.
	if out, err := runUdpSetup(5*time.Minute, "cmake", "--build", buildDir, "--parallel", "2"); err != nil {
		return fmt.Errorf("build badvpn udpgw: %v: %s", err, strings.TrimSpace(out))
	}

	src := filepath.Join(buildDir, "udpgw", "badvpn-udpgw")
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("badvpn build completed but %s was not produced", src)
	}
	if err := os.MkdirAll("/usr/local/bin", 0o755); err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile("/usr/local/bin/badvpn-udpgw", data, 0o755); err != nil {
		return err
	}
	if !BadvpnInstalled() {
		return fmt.Errorf("badvpn-udpgw not found after automatic setup")
	}
	logger.Info("ssh-manager: badvpn-udpgw built and installed automatically")
	return nil
}

func systemdAvailable() bool {
	if !toolExists("systemctl") {
		return false
	}
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

func udpgwArgs(port int) []string {
	args := []string{
		"--listen-addr", fmt.Sprintf("127.0.0.1:%d", port),
		"--max-clients", "512",
		// Games, voice apps and DNS may use several UDP destinations at once.
		"--max-connections-for-client", "64",
	}
	if mtu := udpgwMTU(); mtu > 0 {
		args = append(args, "--udp-mtu", strconv.Itoa(mtu))
	}
	return args
}

func desiredUdpgwUnit(bin string) string {
	args := []string{
		"--listen-addr", "127.0.0.1:%i",
		"--max-clients", "512",
		"--max-connections-for-client", "64",
	}
	if mtu := udpgwMTU(); mtu > 0 {
		args = append(args, "--udp-mtu", strconv.Itoa(mtu))
	}
	return `[Unit]
Description=4x-ui SSH UDP Gateway on port %i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=` + bin + " " + strings.Join(args, " ") + `
Restart=always
RestartSec=1s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`
}

// writeUdpgwSystemdTemplate writes the persistent template and reports whether
// its content changed, so active units are restarted only when necessary.
func writeUdpgwSystemdTemplate() (bool, error) {
	bin, err := badvpnBinary()
	if err != nil {
		return false, err
	}
	want := []byte(desiredUdpgwUnit(bin))
	old, _ := os.ReadFile(udpgwUnitTemplatePath)
	changed := string(old) != string(want)
	if changed {
		if err := os.WriteFile(udpgwUnitTemplatePath, want, 0o644); err != nil {
			return false, err
		}
	}
	var sys sshSystem
	if changed {
		if out, err := sys.run("systemctl", "daemon-reload"); err != nil {
			return false, fmt.Errorf("systemd daemon-reload for UDPGW: %v: %s", err, strings.TrimSpace(out))
		}
	}
	return changed, nil
}

func readUdpgwState() map[int]struct{} {
	ports := map[int]struct{}{}
	raw, err := os.ReadFile(udpgwStatePath)
	if err != nil {
		return ports
	}
	for _, f := range strings.Fields(string(raw)) {
		p, err := strconv.Atoi(f)
		if err == nil && p > 0 && p <= 65535 {
			ports[p] = struct{}{}
		}
	}
	return ports
}

func sortedPorts(ports map[int]struct{}) []int {
	out := make([]int, 0, len(ports))
	for p := range ports {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

func writeUdpgwState(ports map[int]struct{}) error {
	if len(ports) == 0 {
		_ = os.Remove(udpgwStatePath)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(udpgwStatePath), 0o755); err != nil {
		return err
	}
	vals := sortedPorts(ports)
	parts := make([]string, 0, len(vals))
	for _, p := range vals {
		parts = append(parts, strconv.Itoa(p))
	}
	return os.WriteFile(udpgwStatePath, []byte(strings.Join(parts, "\n")+"\n"), 0o600)
}

func udpgwListenerHealthy(port int) bool {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := net.DialTimeout("tcp", addr, 150*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func waitUdpgwReady(port int) error {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(8 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("UDPGW did not begin listening on %s: %v", addr, lastErr)
}

func unitNameForPort(port int) string {
	return fmt.Sprintf("xui-udpgw@%d.service", port)
}

func unitActive(sys sshSystem, unit string) bool {
	_, err := sys.run("systemctl", "is-active", "--quiet", unit)
	return err == nil
}

func recentUnitLog(sys sshSystem, unit string) string {
	if !toolExists("journalctl") {
		return ""
	}
	out, _ := sys.run("journalctl", "-u", unit, "-n", "20", "--no-pager")
	return strings.TrimSpace(out)
}

func stopSystemdUdpRelays() error {
	old := readUdpgwState()
	if len(old) == 0 {
		return nil
	}
	var sys sshSystem
	remaining := map[int]struct{}{}
	var failures []string
	for _, port := range sortedPorts(old) {
		unit := unitNameForPort(port)
		if out, err := sys.run("systemctl", "disable", "--now", unit); err != nil {
			remaining[port] = struct{}{}
			failures = append(failures, fmt.Sprintf("%s: %v (%s)", unit, err, strings.TrimSpace(out)))
		}
	}
	if err := writeUdpgwState(remaining); err != nil {
		return fmt.Errorf("save UDPGW service state: %w", err)
	}
	if len(failures) > 0 {
		return fmt.Errorf("stop UDPGW service: %s", strings.Join(failures, "; "))
	}
	return nil
}

func reconcileSystemdUdpRelays(desired map[int]struct{}) error {
	changed, err := writeUdpgwSystemdTemplate()
	if err != nil {
		return err
	}
	old := readUdpgwState()
	var sys sshSystem
	startedNew := []int{}

	// Bring every desired listener up before removing old ones. The common Save
	// path is intentionally cheap: a listener previously owned by 4x-ui whose
	// template is unchanged and whose TCP socket is healthy needs no systemctl
	// call and no 8-second startup wait.
	for _, port := range sortedPorts(desired) {
		unit := unitNameForPort(port)
		_, wasOld := old[port]
		healthy := udpgwListenerHealthy(port)
		if wasOld && !changed && healthy {
			continue
		}

		// New, stopped, unhealthy, or template-changed units need systemd work.
		// Re-assert enablement only on this slow/recovery path, not every Save.
		if out, enableErr := sys.run("systemctl", "enable", unit); enableErr != nil {
			return fmt.Errorf("enable %s: %v: %s", unit, enableErr, strings.TrimSpace(out))
		}
		active := unitActive(sys, unit)
		var out string
		var startErr error
		switch {
		case changed && active:
			out, startErr = sys.run("systemctl", "restart", unit)
		case active && !healthy:
			// A service can be 'active' before its listener is usable or after an
			// abnormal child state. Restart it rather than waiting eight seconds
			// for a socket that is already known to be absent.
			out, startErr = sys.run("systemctl", "restart", unit)
		case !active:
			out, startErr = sys.run("systemctl", "start", unit)
		}
		if startErr != nil {
			if !wasOld {
				_, _ = sys.run("systemctl", "disable", "--now", unit)
			}
			logTail := recentUnitLog(sys, unit)
			return fmt.Errorf("start %s: %v: %s%s", unit, startErr, strings.TrimSpace(out), func() string {
				if logTail == "" {
					return ""
				}
				return "\n" + logTail
			}())
		}
		if err := waitUdpgwReady(port); err != nil {
			if !wasOld {
				_, _ = sys.run("systemctl", "disable", "--now", unit)
			}
			return fmt.Errorf("%v\n%s", err, recentUnitLog(sys, unit))
		}
		if !wasOld {
			startedNew = append(startedNew, port)
		}
	}

	// Retire stale listeners after every desired listener is healthy. If one
	// cannot be stopped, keep it in the ownership state so a later reconcile or
	// uninstall can retry instead of orphaning a 4x-ui-created service.
	ownedState := make(map[int]struct{}, len(desired))
	for port := range desired {
		ownedState[port] = struct{}{}
	}
	for _, port := range sortedPorts(old) {
		if _, keep := desired[port]; keep {
			continue
		}
		unit := unitNameForPort(port)
		if out, err := sys.run("systemctl", "disable", "--now", unit); err != nil {
			logger.Warningf("ssh-manager: could not stop stale %s: %v (%s)", unit, err, strings.TrimSpace(out))
			ownedState[port] = struct{}{}
		}
	}

	if err := writeUdpgwState(ownedState); err != nil {
		for _, port := range startedNew {
			_, _ = sys.run("systemctl", "disable", "--now", unitNameForPort(port))
		}
		return fmt.Errorf("save UDPGW service state: %w", err)
	}
	return nil
}

// udpRelayProc is a non-systemd fallback used by containers/minimal systems.
// It is keyed by relay port, not inbound ID, so multiple SSH inbounds can share
// the standard 127.0.0.1:7300 UDPGW listener without bind conflicts.
type udpRelayProc struct {
	port   int
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

var (
	udpRelayMu sync.Mutex
	udpRelays  = map[int]*udpRelayProc{} // key: UDPGW port
)

func startUdpRelay(port int) {
	ctx, cancel := context.WithCancel(context.Background())
	proc := &udpRelayProc{port: port, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	udpRelayMu.Lock()
	udpRelays[port] = proc
	udpRelayMu.Unlock()
	go proc.supervise()
}

func (p *udpRelayProc) supervise() {
	defer func() {
		udpRelayMu.Lock()
		if udpRelays[p.port] == p {
			delete(udpRelays, p.port)
		}
		udpRelayMu.Unlock()
		close(p.done)
	}()
	failures := 0
	for {
		select {
		case <-p.ctx.Done():
			return
		default:
		}
		if err := p.run(); err != nil {
			failures++
			logger.Warningf("ssh-manager: udpgw port %d crashed (attempt %d): %v", p.port, failures, err)
			if failures >= 10 {
				logger.Errorf("ssh-manager: udpgw port %d giving up after %d failures", p.port, failures)
				return
			}
			delay := time.Duration(failures) * 2 * time.Second
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
			select {
			case <-p.ctx.Done():
				return
			case <-time.After(delay):
			}
		} else {
			return
		}
	}
}

func (p *udpRelayProc) run() error {
	bin, err := badvpnBinary()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(p.ctx, bin, udpgwArgs(p.port)...)
	logger.Infof("ssh-manager: fallback udpgw up 127.0.0.1:%d", p.port)
	err = cmd.Run()
	if p.ctx.Err() != nil {
		return nil
	}
	return err
}

func reconcileFallbackUdpRelays(desired map[int]struct{}) error {
	udpRelayMu.Lock()
	toStop := []*udpRelayProc{}
	for port, proc := range udpRelays {
		if _, ok := desired[port]; !ok {
			delete(udpRelays, port)
			toStop = append(toStop, proc)
		}
	}
	toStart := []int{}
	for port := range desired {
		if _, running := udpRelays[port]; !running {
			toStart = append(toStart, port)
		}
	}
	udpRelayMu.Unlock()

	for _, p := range toStop {
		p.cancel()
		waitChanWithTimeout(p.done, "udp relay (reconcile)")
	}
	sort.Ints(toStart)
	for _, port := range toStart {
		startUdpRelay(port)
		if err := waitUdpgwReady(port); err != nil {
			return err
		}
	}
	return nil
}

// reconcileUdpRelays makes the live VPS UDPGW listeners match enabled SSH
// inbounds. The desired input is inboundID -> relayPort. Identical ports are
// intentionally deduplicated so the default 7300 can be shared.
func reconcileUdpRelays(desiredByInbound map[int]int) error {
	desired := map[int]struct{}{}
	for _, port := range desiredByInbound {
		if port > 0 && port <= 65535 {
			desired[port] = struct{}{}
		}
	}
	if len(desired) == 0 {
		// Do not require/install BadVPN when no inbound asks for UDP. If an old
		// 4x-ui UDPGW state exists, retire only those owned instances.
		if systemdAvailable() {
			return stopSystemdUdpRelays()
		}
		return reconcileFallbackUdpRelays(desired)
	}
	if err := EnsureBadvpn(); err != nil {
		return err
	}
	if systemdAvailable() {
		return reconcileSystemdUdpRelays(desired)
	}
	return reconcileFallbackUdpRelays(desired)
}

// StopAllUdpRelays stops only in-process fallback relays. systemd-managed UDPGW
// listeners intentionally survive panel restarts/updates and are reconciled on
// the next start. Uninstall removes only the units recorded as 4x-ui-owned.
func StopAllUdpRelays() {
	udpRelayMu.Lock()
	procs := make([]*udpRelayProc, 0, len(udpRelays))
	for _, p := range udpRelays {
		procs = append(procs, p)
	}
	udpRelays = map[int]*udpRelayProc{}
	udpRelayMu.Unlock()
	for _, p := range procs {
		p.cancel()
		waitChanWithTimeout(p.done, "udp relay")
	}
}
