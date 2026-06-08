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
		if hasArg(os.Args[1:], adminRelaunchArg) || isProcessElevated() {
			signalRunningInstanceValue(adminRelaunchSignal)
			return waitForSingleInstance(createMutex, closeHandle, uintptr(unsafe.Pointer(name)), 15*time.Second)
		}
		signalRunningInstance(os.Args[1:])
		return func() {}, false, nil
	}
	return func() {
		closeHandle.Call(handle)
	}, true, nil
}

func waitForSingleInstance(createMutex, closeHandle *syscall.LazyProc, name uintptr, timeout time.Duration) (func(), bool, error) {
	deadline := time.Now().Add(timeout)
	const errorAlreadyExists = 183
	for time.Now().Before(deadline) {
		handle, _, callErr := createMutex.Call(0, 1, name)
		if handle == 0 {
			return nil, false, callErr
		}
		if callErr != syscall.Errno(errorAlreadyExists) {
			return func() {
				closeHandle.Call(handle)
			}, true, nil
		}
		closeHandle.Call(handle)
		time.Sleep(250 * time.Millisecond)
	}
	signalRunningInstance(os.Args[1:])
	return func() {}, false, nil
}

func hasArg(args []string, target string) bool {
	for _, arg := range args {
		if arg == target {
			return true
		}
	}
	return false
}

func singleInstanceDataDir() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		configDir = "."
	}
	return filepath.Join(configDir, "Pulse")
}

func signalRunningInstance(args []string) {
	value := time.Now().Format(time.RFC3339Nano)
	for _, arg := range args {
		if arg != "" {
			value = arg
			break
		}
	}
	signalRunningInstanceValue(value)
}

func signalRunningInstanceValue(value string) {
	dir := singleInstanceDataDir()
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(filepath.Join(dir, "show.signal"), []byte(value), 0o644)
}
