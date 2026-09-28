//go:build windows

package daemon

import "os"

// TODO: LockFileEx. Until then Windows runs without single-instance protection.
func tryLock(*os.File) error { return nil }
func unlock(*os.File) error  { return nil }
