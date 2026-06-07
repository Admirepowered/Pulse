//go:build darwin
// +build darwin

package pulse

type trayMenuItem struct{}

func StartTray(app *App) {}

func quitTray() {}

func (a *App) updateTrayMenuState() {}
