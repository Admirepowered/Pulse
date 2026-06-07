//go:build !windows

package pulse

import (
	"errors"
	"os"
	"path/filepath"
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
