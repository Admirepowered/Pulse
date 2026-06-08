//go:build !windows

package pulse

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

func AcquireSingleInstance() (func(), bool, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		configDir = "."
	}
	dir := filepath.Join(configDir, "Pulse")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, false, err
	}
	lockPath := filepath.Join(dir, "pulse.lock")
	// Use flock(LOCK_EX|LOCK_NB) instead of O_EXCL. The kernel releases
	// the lock automatically when the process dies (clean exit, crash,
	// SIGKILL, or system reboot), so a stale pulse.lock can never block
	// a new launch. The file itself is harmless if left behind.
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		signalRunningInstance(os.Args[1:])
		return func() {}, false, nil
	}
	// Best-effort: write our PID so a human can inspect who holds the
	// lock. The lock itself is the kernel's, not the file contents.
	_, _ = file.WriteString(strconv.Itoa(os.Getpid()))
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, true, nil
}

func singleInstanceDataDir() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		configDir = "."
	}
	return filepath.Join(configDir, "Pulse")
}

func signalRunningInstance(args []string) {
	dir := singleInstanceDataDir()
	_ = os.MkdirAll(dir, 0o755)
	value := time.Now().Format(time.RFC3339Nano)
	hasVisibleSignal := false
	for _, arg := range args {
		if arg == "--start-hidden" || arg == "-start-hidden" {
			continue
		}
		if arg != "" {
			value = arg
			hasVisibleSignal = true
			break
		}
	}
	if len(args) > 0 && !hasVisibleSignal {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, "show.signal"), []byte(value), 0o644)
}

// avoid unused import errors when errcheck sweeps the file
var _ = errors.New
