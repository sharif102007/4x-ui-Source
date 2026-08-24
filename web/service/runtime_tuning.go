package service

import (
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/v4/mem"

	"github.com/sharif102007/4x-ui/v2/logger"
)

// Go runtime tuning.
//
// The panel keeps a lot of short-lived garbage alive between GC cycles: client
// settings are stored as JSON strings and unmarshalled on nearly every request,
// so a large inbound produces multi-MB allocations per call. With Go's default
// behaviour the heap is allowed to double before a collection runs, which on a
// 1 GB VPS is enough to get the process OOM-killed under a burst rather than
// simply collecting sooner.
//
// debug.SetMemoryLimit gives the GC a *soft* ceiling: as the heap approaches
// it, collections become more frequent instead of the heap growing further.
// It never causes an allocation to fail, so the worst case of setting it is
// more CPU spent in GC - not a new failure mode.
//
// Deliberately conservative: 75% of what the process is actually allowed to
// use, leaving room for the Go runtime's own off-heap memory (stacks, mmap'd
// spans) plus the Xray child process.

const memoryLimitFraction = 75 // percent

// cgroupMemoryLimit returns the container memory limit in bytes, or 0 when
// unlimited or unavailable. Checked before host RAM because gopsutil reports
// /proc/meminfo, which inside a memory-capped container describes the host and
// would produce a limit far above what the cgroup actually allows.
func cgroupMemoryLimit() uint64 {
	// cgroup v2
	if raw, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		v := strings.TrimSpace(string(raw))
		if v != "max" {
			if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 {
				return n
			}
		}
	}
	// cgroup v1
	if raw, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		if n, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64); err == nil {
			// v1 reports a sentinel close to max-uint64 when unlimited.
			if n > 0 && n < (1<<62) {
				return n
			}
		}
	}
	return 0
}

// ApplyRuntimeTuning sets a soft heap ceiling for the GC. Called once at
// startup. Any failure to determine the available memory leaves the Go
// defaults untouched.
//
// Override with XUI_MEMORY_LIMIT=<bytes> in the environment file, or
// XUI_MEMORY_LIMIT=0 to disable this entirely and keep stock Go behaviour.
func ApplyRuntimeTuning() {
	if raw := os.Getenv("XUI_MEMORY_LIMIT"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 0 {
			logger.Warningf("runtime: ignoring invalid XUI_MEMORY_LIMIT=%q", raw)
		} else if n == 0 {
			logger.Info("runtime: memory limit disabled by XUI_MEMORY_LIMIT=0")
			return
		} else {
			debug.SetMemoryLimit(n)
			logger.Infof("runtime: soft memory limit set to %d MiB (from XUI_MEMORY_LIMIT), GOMAXPROCS=%d",
				n/(1<<20), runtime.GOMAXPROCS(0))
			return
		}
	}

	available := cgroupMemoryLimit()
	if available == 0 {
		vm, err := mem.VirtualMemory()
		if err != nil || vm == nil || vm.Total == 0 {
			logger.Debug("runtime: could not determine available memory, leaving GC defaults")
			return
		}
		available = vm.Total
	}

	limit := int64(available / 100 * memoryLimitFraction)
	if limit <= 0 {
		return
	}
	debug.SetMemoryLimit(limit)
	logger.Infof("runtime: soft memory limit set to %d MiB of %d MiB available, GOMAXPROCS=%d",
		limit/(1<<20), available/(1<<20), runtime.GOMAXPROCS(0))
}
