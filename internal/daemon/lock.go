// Package daemon holds the background agent's plumbing: a single-instance
// lock and OS service integration (launchd on macOS, systemd on Linux).
package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/syncmyenv/core/internal/config"
)

// ErrRunning means another daemon already holds the lock.
var ErrRunning = errors.New("daemon already running")

// Lock is held for the daemon's lifetime; the OS releases it if we crash.
type Lock struct{ f *os.File }

func lockPath() (string, error) {
	h, err := config.Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "daemon.lock"), nil
}

// Acquire takes the single-instance lock and records our pid.
func Acquire() (*Lock, error) {
	p, err := lockPath()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := tryLock(f); err != nil {
		f.Close()
		if pid := readPID(p); pid > 0 {
			return nil, fmt.Errorf("%w (pid %d)", ErrRunning, pid)
		}
		return nil, ErrRunning
	}
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	return &Lock{f: f}, nil
}

// Release drops the lock.
func (l *Lock) Release() {
	_ = unlock(l.f)
	_ = l.f.Close()
}

// Running reports whether a daemon holds the lock, and its pid.
func Running() (bool, int) {
	p, err := lockPath()
	if err != nil {
		return false, 0
	}
	f, err := os.OpenFile(p, os.O_RDWR, 0o600)
	if err != nil {
		return false, 0
	}
	defer f.Close()
	if err := tryLock(f); err != nil {
		return true, readPID(p)
	}
	_ = unlock(f)
	return false, 0
}

func readPID(p string) int {
	b, _ := os.ReadFile(p)
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}
