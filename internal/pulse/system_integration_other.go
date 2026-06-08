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
