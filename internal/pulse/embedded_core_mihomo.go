//go:build !windows || pulse_embed_mihomo

// This file implements the **app-embedded** core path: mihomo is linked into
// the Pulse app itself (build tag `pulse_embed_mihomo`) and runs in-process.
// On non-Windows this is the only path. When the app is built with the
// embedded tag, the `AutoStartService` boot service is unnecessary because
// Pulse can autostart via the `Run` registry and run the core in-process.
package pulse

import (
	"net/url"
	"os"
	"time"

	mihomoObservable "github.com/metacubex/mihomo/common/observable"
	mihomoMemory "github.com/metacubex/mihomo/component/memory"
	mihomoConfig "github.com/metacubex/mihomo/config"
	mihomoConstant "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/hub/route"
	mihomoLog "github.com/metacubex/mihomo/log"
)

func appHasEmbeddedCore() bool {
	return true
}

func (a *App) startEmbeddedCore(runtimeConfig string, settings Settings) error {
	configBytes, err := os.ReadFile(runtimeConfig)
	if err != nil {
		return err
	}
	a.startMihomoLogSubscription()
	mihomoConstant.SetHomeDir(a.dataDir)
	mihomoConstant.SetConfig(runtimeConfig)
	if err := mihomoConfig.Init(mihomoConstant.Path.HomeDir()); err != nil {
		return err
	}
	route.SetEmbedMode(true)
	controller := "127.0.0.1:9090"
	if parsed, err := url.Parse(settings.ApiBase); err == nil && parsed.Host != "" {
		controller = parsed.Host
	}
	if err := hub.Parse(configBytes, hub.WithExternalController(controller), hub.WithSecret(settings.Secret)); err != nil {
		a.stopMihomoLogSubscription()
		return err
	}
	a.mu.Lock()
	a.embeddedCoreRunning = true
	a.startedAt = time.Now().Unix()
	a.mu.Unlock()
	a.appendLog("info", "embedded mihomo core started")
	return nil
}

func (a *App) stopEmbeddedCore() {
	route.ReCreateServer(&route.Config{})
	executor.Shutdown()
	a.stopMihomoLogSubscription()
}

func (a *App) startMihomoLogSubscription() {
	a.mu.Lock()
	if a.embeddedLogSub != nil {
		a.mu.Unlock()
		return
	}
	sub := mihomoLog.Subscribe()
	a.embeddedLogSub = sub
	a.mu.Unlock()
	go func() {
		for event := range sub {
			a.appendDataLog("mihomo.log", event.Type(), event.Payload)
			a.mu.Lock()
			a.logLines = append(a.logLines, LogLine{Time: time.Now().Unix(), Level: event.Type(), Message: event.Payload})
			if len(a.logLines) > 500 {
				a.logLines = append([]LogLine(nil), a.logLines[len(a.logLines)-500:]...)
			}
			a.mu.Unlock()
		}
	}()
}

func (a *App) stopMihomoLogSubscription() {
	a.mu.Lock()
	sub, _ := a.embeddedLogSub.(mihomoObservable.Subscription[mihomoLog.Event])
	a.embeddedLogSub = nil
	a.mu.Unlock()
	if sub != nil {
		mihomoLog.UnSubscribe(sub)
	}
}

func (a *App) coreMemoryUsage() uint64 {
	pid := os.Getpid()
	a.mu.Lock()
	if a.coreCmd != nil && a.coreCmd.Process != nil {
		pid = a.coreCmd.Process.Pid
	}
	a.mu.Unlock()
	stat, err := mihomoMemory.GetMemoryInfo(int32(pid))
	if err != nil || stat == nil {
		return 0
	}
	return stat.RSS
}

func (a *App) applyEmbeddedRuntimeSettings(settings Settings) {
	if level, ok := mihomoLog.LogLevelMapping[normalizeLogLevel(settings.LogLevel)]; ok {
		mihomoLog.SetLevel(level)
	}
	a.appendLog("info", "embedded runtime settings applied locally; restart core if TUN or listener settings do not change immediately")
}
