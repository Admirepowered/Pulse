//go:build !windows

package pulse

func setAutoStart(enabled bool) error {
	return nil
}

func registerURLProtocol() error {
	return nil
}

func configureSystemProxy(settings Settings, enabled bool) error {
	return nil
}

func systemProxyState() string {
	return "system proxy integration is not implemented on this platform"
}

func isProcessElevated() bool {
	return true
}

func relaunchAsAdministrator() error {
	return nil
}

// relaunchAsAdministratorWithArgs is unreachable on non-Windows because
// isProcessElevated() always returns true there (the surrounding caller
// only triggers the relaunch when not elevated). The stub exists so
// app.go compiles cross-platform.
func relaunchAsAdministratorWithArgs(extraArgs []string) error {
	return nil
}
