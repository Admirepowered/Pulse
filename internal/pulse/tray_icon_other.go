//go:build !windows && !darwin
// +build !windows,!darwin

package pulse

func (a *App) installTrayDoubleClickHandler() {}
