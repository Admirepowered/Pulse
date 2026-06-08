//go:build darwin
// +build darwin

package pulse

/*
#cgo darwin LDFLAGS: -framework AppKit -framework Foundation
void PulseInstallDarwinTray(void);
void PulseRemoveDarwinTray(void);
*/
import "C"

import "sync"

type trayMenuItem struct{}

var darwinTrayState struct {
	sync.Mutex
	app *App
}

func StartTray(app *App) {
	darwinTrayState.Lock()
	darwinTrayState.app = app
	darwinTrayState.Unlock()
	C.PulseInstallDarwinTray()
	if app != nil {
		app.appendLog("info", "macOS native status tray registered")
	}
}

func quitTray() {
	C.PulseRemoveDarwinTray()
}

func (a *App) updateTrayMenuState() {}

//export PulseDarwinTrayAction
func PulseDarwinTrayAction(action C.int) {
	darwinTrayState.Lock()
	app := darwinTrayState.app
	darwinTrayState.Unlock()
	if app == nil {
		return
	}
	switch int(action) {
	case 1:
		app.ShowWindow()
	case 2:
		app.CloseWindow()
	case 3:
		app.quitApplication()
	}
}
