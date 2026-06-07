//go:build !windows

package pulse

import (
	"errors"
	"os"
	"path/filepath"
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
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if errors.Is(err, os.ErrExist) {
		signalRunningInstance()
		return func() {}, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return func() {
		_ = file.Close()
		_ = os.Remove(lockPath)
	}, true, nil
}

func singleInstanceDataDir() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		configDir = "."
	}
	return filepath.Join(configDir, "Pulse")
}

func signalRunningInstance() {
	dir := singleInstanceDataDir()
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(filepath.Join(dir, "show.signal"), []byte(time.Now().Format(time.RFC3339Nano)), 0o644)
}
