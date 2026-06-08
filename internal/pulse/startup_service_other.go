//go:build !windows

package pulse

func syncStartupServicePayload(dataDir string) error {
	return nil
}

func setServiceAutoStart(dataDir string, enabled bool) error {
	return nil
}
