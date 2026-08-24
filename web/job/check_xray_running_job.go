// Package job provides background job implementations for the 4x-ui web panel,
// including traffic monitoring, system checks, and periodic maintenance tasks.
package job

import (
	"github.com/sharif102007/4x-ui/v2/logger"
	"github.com/sharif102007/4x-ui/v2/web/service"
)

// maxRestartBackoffShift caps the exponential backoff between restart attempts
// at 2^6 = 64 check intervals.
const maxRestartBackoffShift = 6

// CheckXrayRunningJob monitors Xray process health and restarts it if it crashes.
type CheckXrayRunningJob struct {
	xrayService service.XrayService
	checkTime   int

	// failures counts consecutive failed restart attempts and skip is how many
	// check intervals remain before the next attempt. Without them a config that
	// can never start - a TLS inbound pointing at a certificate that is not on
	// disk being the usual cause - was retried on every single tick forever,
	// spawning a doomed process and filling the log each time.
	failures int
	skip     int
}

// NewCheckXrayRunningJob creates a new Xray health check job instance.
func NewCheckXrayRunningJob() *CheckXrayRunningJob {
	return new(CheckXrayRunningJob)
}

// Run checks if Xray has crashed and restarts it after confirming it's down for
// 2 consecutive checks, backing off exponentially while restarts keep failing.
func (j *CheckXrayRunningJob) Run() {
	if !j.xrayService.DidXrayCrash() {
		j.checkTime = 0
		j.failures = 0
		j.skip = 0
		return
	}

	if j.skip > 0 {
		j.skip--
		return
	}

	j.checkTime++
	// only restart if it's down 2 times in a row
	if j.checkTime <= 1 {
		return
	}
	j.checkTime = 0

	if err := j.xrayService.RestartXray(false); err != nil {
		j.failures++
		shift := j.failures
		if shift > maxRestartBackoffShift {
			shift = maxRestartBackoffShift
		}
		j.skip = 1 << shift
		logger.Errorf("Restart xray failed (attempt %d, next retry after %d checks): %v",
			j.failures, j.skip, err)
		return
	}

	j.failures = 0
	j.skip = 0
	logger.Info("Xray restarted after a crash")
}
