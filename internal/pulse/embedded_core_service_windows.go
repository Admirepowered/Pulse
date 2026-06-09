//go:build windows && !pulse_embed_mihomo

// This file implements the **helper-managed** core path for Windows builds
// that do not embed mihomo into the Pulse app. The app spawns
// `PulseStartupService.exe` as a child process that acts as the core. The
// helper itself either embeds mihomo (when built with
// `pulse_service_embed_mihomo`) or launches an external `mihomo.exe` resolved
// from `settings.CorePath`. This is the "core itself starts PulseStartupService
// as the core" path used when neither the app nor the service has mihomo
// linked in, and also when the service has mihomo embedded but the user picks
// the embedded CoreMode instead of registering the service.
package pulse

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func appHasEmbeddedCore() bool {
	return false
}

func (a *App) startEmbeddedCore(runtimeConfig string, settings Settings) error {
	if coreAPIIsReachable(settings.ApiBase, settings.Secret) {
		a.mu.Lock()
		a.embeddedCoreRunning = true
		a.startedAt = time.Now().Unix()
		a.mu.Unlock()
		a.appendLog("info", "managed core already reachable through PulseStartupService")
		return nil
	}
	cmd, err := startManagedHelperCore(a.dataDir, settings, runtimeConfig)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.coreCmd = cmd
	a.embeddedCoreRunning = true
	a.startedAt = time.Now().Unix()
	a.mu.Unlock()
	a.appendLog("info", "managed core started through PulseStartupService")
	go func() {
		err := cmd.Wait()
		a.mu.Lock()
		if a.coreCmd == cmd {
			a.coreCmd = nil
			a.embeddedCoreRunning = false
			a.startedAt = 0
		}
		a.mu.Unlock()
		if err != nil {
			a.appendLog("error", "managed core stopped: "+err.Error())
			return
		}
		a.appendLog("info", "managed core stopped")
	}()
	return nil
}

func (a *App) stopEmbeddedCore() {
	if err := stopServiceCore(a.dataDir); err != nil {
		a.appendLog("warn", "managed core stop failed: "+err.Error())
		return
	}
	a.appendLog("info", "managed core stop requested")
}

func (a *App) reloadManagedRuntimeConfig(runtimeConfig string, settings Settings) (bool, error) {
	if !serviceHelperHasEmbeddedCore() || settings.CoreMode == "custom" {
		return false, nil
	}
	signalPath := filepath.Join(a.dataDir, "pulse-core-reload.signal")
	if err := os.WriteFile(signalPath, []byte(time.Now().Format(time.RFC3339Nano)), 0o644); err != nil {
		return true, err
	}
	a.appendLog("info", "managed core config reload requested")
	return true, nil
}

func (a *App) coreMemoryUsage() uint64 {
	return 0
}

func (a *App) applyEmbeddedRuntimeSettings(settings Settings) {
	body := map[string]any{
		"allow-lan": settings.AllowLan,
		"mode":      settings.Mode,
		"log-level": normalizeLogLevel(settings.LogLevel),
		"tun":       tunConfigMap(settings),
	}
	if name := strings.TrimSpace(settings.TunInterface); name != "" {
		body["interface-name"] = name
	}
	if err := a.apiRequest(http.MethodPatch, "/configs", body, nil); err != nil {
		a.appendLog("warn", "managed core runtime settings failed: "+err.Error())
	}
}
