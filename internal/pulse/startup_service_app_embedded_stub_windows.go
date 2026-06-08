//go:build windows && pulse_embed_mihomo

package pulse

// ensureStartupServiceExecutable is unused in the app-embedded build:
// the app runs mihomo in-process and never needs the Windows service
// helper, so this is a compile-time placeholder. Callers in
// startup_service_windows.go still resolve to this function on the
// app-embedded build; they just see an empty service path and bail
// out at runtime (no UI surfaces a service toggle in this build).

func ensureStartupServiceExecutable(dataDir string) (string, error) {
	return "", nil
}
