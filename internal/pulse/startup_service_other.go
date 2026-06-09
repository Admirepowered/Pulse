//go:build !windows

package pulse

func syncStartupServiceExecutable(dataDir string) error {
	return nil
}

func syncStartupServicePayload(dataDir string, settings Settings) error {
	return nil
}

func setServiceAutoStart(dataDir string, settings Settings, enabled bool) error {
	return nil
}

func startupServiceBuildStatus(dataDir string, settings Settings) (string, bool) {
	return "", false
}

func startServiceCore(dataDir string, settings Settings, runtimeConfig string) error {
	return nil
}

func stopServiceCore(dataDir string) error {
	return nil
}

func isCoreServiceRunning() bool {
	return false
}
