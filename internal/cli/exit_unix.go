//go:build unix

package cli

import (
	"os"
	"syscall"
)

// signalExitCode reports the POSIX convention exit code (128 + signal
// number) when the child process was terminated by a signal, so callers and
// CI scripts can distinguish e.g. SIGINT (130) from SIGKILL (137) instead of
// seeing ExitCode()'s opaque -1 truncated to 255 for every signal.
func signalExitCode(state *os.ProcessState) (int, bool) {
	if state == nil {
		return 0, false
	}
	status, ok := state.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() {
		return 0, false
	}
	return 128 + int(status.Signal()), true
}
