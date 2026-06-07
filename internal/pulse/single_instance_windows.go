//go:build windows

package pulse

import (
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

func AcquireSingleInstance() (func(), bool, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	createMutex := kernel32.NewProc("CreateMutexW")
	closeHandle := kernel32.NewProc("CloseHandle")
	name, err := syscall.UTF16PtrFromString(`Local\AdmirepoweredPulseSingleInstance`)
	if err != nil {
		return nil, false, err
	}
	handle, _, callErr := createMutex.Call(0, 1, uintptr(unsafe.Pointer(name)))
	if handle == 0 {
		return nil, false, callErr
	}
	const errorAlreadyExists = 183
	if callErr == syscall.Errno(errorAlreadyExists) {
		closeHandle.Call(handle)
		signalRunningInstance()
		return func() {}, false, nil
	}
	return func() {
		closeHandle.Call(handle)
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
