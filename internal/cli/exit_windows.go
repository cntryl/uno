//go:build windows

package cli

import "os"

// signalExitCode is a no-op on Windows: there is no POSIX signal delivery to
// mirror, and os.ProcessState's exit code already reflects however the
// process was terminated.
func signalExitCode(*os.ProcessState) (int, bool) {
	return 0, false
}
