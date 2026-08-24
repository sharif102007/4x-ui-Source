package service

import (
	"sync"
	"time"

	"github.com/sharif102007/4x-ui/v2/logger"
)

// shutdownDrainTimeout bounds how long any single component may take to drain
// while the panel is shutting down.
const shutdownDrainTimeout = 5 * time.Second

// waitWithTimeout waits for wg, giving up after shutdownDrainTimeout.
//
// Every wait on the shutdown path used to be unbounded. The SSH payload gateway
// was the worst case: closing its listener stops new connections, but the tunnels
// already established are long-lived by nature - an SSH session can stay open for
// hours - so a single connected user made SIGTERM handling block until systemd's
// stop timeout expired and SIGKILL arrived. That is what made `x-ui update`
// appear to freeze at "Stopping x-ui...".
//
// Giving up is the right call here: the process is about to exit, so leaking a
// goroutine for the last few milliseconds of its life costs nothing, while
// blocking forever costs the user a 90-second hang and a killed process.
func waitWithTimeout(wg *sync.WaitGroup, what string) {
	if wg == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(shutdownDrainTimeout):
		logger.Warningf("shutdown: %s did not drain within %s; continuing", what, shutdownDrainTimeout)
	}
}

// waitChanWithTimeout waits for ch to deliver or close, bounded the same way.
func waitChanWithTimeout(ch <-chan struct{}, what string) {
	if ch == nil {
		return
	}
	select {
	case <-ch:
	case <-time.After(shutdownDrainTimeout):
		logger.Warningf("shutdown: %s did not exit within %s; continuing", what, shutdownDrainTimeout)
	}
}
