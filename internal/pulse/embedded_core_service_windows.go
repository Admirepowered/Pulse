//go:build windows && !pulse_embed_mihomo

package pulse

import (
	"net/http"
	"strings"
	"time"
)

func (a *App) startEmbeddedCore(runtimeConfig string, settings Settings) error {
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
