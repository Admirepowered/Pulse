//go:build !windows

package pulse

func syncStartupServicePayload(dataDir string, settings Settings) error {
	return nil
}

func setServiceAutoStart(dataDir string, settings Settings, enabled bool) error {
	return nil
}
