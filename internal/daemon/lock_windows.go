//go:build windows

package daemon

import (
	"os"

	"golang.org/x/sys/windows"
)

// LockFileEx on the first byte: exclusive, non-blocking. Released by the OS
// when the process exits, like flock on Unix.
func tryLock(f *os.File) error {
	ol := new(windows.Overlapped)
	return windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
}

func unlock(f *os.File) error {
	ol := new(windows.Overlapped)
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol)
}
