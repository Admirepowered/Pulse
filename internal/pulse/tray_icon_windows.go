//go:build windows
// +build windows

package pulse

import (
	"os"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	trayUser32                     = windows.NewLazySystemDLL("user32.dll")
	procTrayCallWindowProcW        = trayUser32.NewProc("CallWindowProcW")
	procTrayDefWindowProcW         = trayUser32.NewProc("DefWindowProcW")
	procTrayEnumWindows            = trayUser32.NewProc("EnumWindows")
	procTrayGetClassNameW          = trayUser32.NewProc("GetClassNameW")
	procTrayGetWindowThreadProcess = trayUser32.NewProc("GetWindowThreadProcessId")
	procTraySetWindowLongPtrW      = trayUser32.NewProc("SetWindowLongPtrW")
)

const (
	trayGwlpWndProc      = ^uintptr(3)
	trayWmUser           = 0x0400
	trayWmSystrayMessage = trayWmUser + 1
	trayWmLButtonUp      = 0x0202
	trayDoubleClickMs    = 350
)

func (a *App) installTrayDoubleClickHandler() {
	if atomic.LoadUintptr(&a.trayWndProc) != 0 {
		return
	}
	hwnd := findSystrayWindowForCurrentProcess()
	if hwnd == 0 {
		a.appendLog("warning", "tray double-click handler skipped: systray window not found")
		return
	}
	callback := windows.NewCallback(func(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
		if message == trayWmSystrayMessage {
			if lParam == trayWmLButtonUp {
				now := time.Now().UnixMilli()
				last := atomic.SwapInt64(&a.trayLastLeftClick, int64(now))
				if last > 0 && now-last <= trayDoubleClickMs {
					atomic.StoreInt64(&a.trayLastLeftClick, 0)
					go a.ShowWindow()
				}
				return 0
			}
		}
		if prev := atomic.LoadUintptr(&a.trayPrevWndProc); prev != 0 {
			ret, _, _ := procTrayCallWindowProcW.Call(prev, hwnd, uintptr(message), wParam, lParam)
			return ret
		}
		ret, _, _ := procTrayDefWindowProcW.Call(hwnd, uintptr(message), wParam, lParam)
		return ret
	})
	prev, _, err := procTraySetWindowLongPtrW.Call(hwnd, trayGwlpWndProc, callback)
	if prev == 0 && err != windows.ERROR_SUCCESS {
		a.appendLog("error", "tray double-click handler failed: "+err.Error())
		return
	}
	atomic.StoreUintptr(&a.trayPrevWndProc, prev)
	atomic.StoreUintptr(&a.trayWndProc, callback)
	a.appendLog("info", "tray double-click handler registered")
}

func findSystrayWindowForCurrentProcess() uintptr {
	targetPID := uint32(os.Getpid())
	var found uintptr
	enumCallback := windows.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
		var pid uint32
		procTrayGetWindowThreadProcess.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		if pid != targetPID {
			return 1
		}
		className := make([]uint16, 256)
		n, _, _ := procTrayGetClassNameW.Call(hwnd, uintptr(unsafe.Pointer(&className[0])), uintptr(len(className)))
		if n > 0 && windows.UTF16ToString(className[:n]) == "SystrayClass" {
			found = hwnd
			return 0
		}
		return 1
	})
	procTrayEnumWindows.Call(enumCallback, 0)
	return found
}
