//go:build windows && pulse_service_embed_mihomo

package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	mihomoConfig "github.com/metacubex/mihomo/config"
	mihomoConstant "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/hub/route"
	mihomoLog "github.com/metacubex/mihomo/log"
	"golang.org/x/sys/windows/svc"
)

func runEmbeddedCore(config serviceConfig, requests <-chan svc.ChangeRequest) error {
	if strings.TrimSpace(config.DataDir) == "" {
		return fmt.Errorf("missing dataDir in %s", defaultConfigFile)
	}
	if strings.TrimSpace(config.RuntimeConfig) == "" {
		return fmt.Errorf("missing runtimeConfig in %s", defaultConfigFile)
	}
	mihomoConstant.SetHomeDir(config.DataDir)
	mihomoConstant.SetConfig(config.RuntimeConfig)
	if err := mihomoConfig.Init(mihomoConstant.Path.HomeDir()); err != nil {
		return err
	}
	route.SetEmbedMode(true)
	if err := applyEmbeddedCoreConfig(config); err != nil {
		return err
	}
	stopLogForwarder := startMihomoLogForwarder()
	defer stopLogForwarder()

	writeLog("embedded core started")
	waitForEmbeddedCoreStop(config, requests)
	route.ReCreateServer(&route.Config{})
	executor.Shutdown()
	writeLog("embedded core stopped")
	return nil
}

func applyEmbeddedCoreConfig(config serviceConfig) error {
	configBytes, err := os.ReadFile(config.RuntimeConfig)
	if err != nil {
		return err
	}
	controller := "127.0.0.1:9090"
	if parsed, err := url.Parse(config.ApiBase); err == nil && parsed.Host != "" {
		controller = parsed.Host
	}
	return hub.Parse(configBytes, hub.WithExternalController(controller), hub.WithSecret(config.Secret))
}

func startMihomoLogForwarder() func() {
	sub := mihomoLog.Subscribe()
	go func() {
		for event := range sub {
			if event.LogLevel < mihomoLog.Level() {
				continue
			}
			writeLog("mihomo " + event.Type() + ": " + event.Payload)
		}
	}()
	return func() {
		mihomoLog.UnSubscribe(sub)
	}
}

func waitForEmbeddedCoreStop(config serviceConfig, requests <-chan svc.ChangeRequest) {
	stopMarker := signalModTime(config.StopSignal)
	reloadMarker := signalModTime(config.ReloadSignal)
	for {
		if signalModTime(config.StopSignal).After(stopMarker) {
			writeLog("embedded core stop signal received")
			return
		}
		if nextReloadMarker := signalModTime(config.ReloadSignal); nextReloadMarker.After(reloadMarker) {
			reloadMarker = nextReloadMarker
			if err := applyEmbeddedCoreConfig(config); err != nil {
				writeLog("embedded core reload failed: " + err.Error())
			} else {
				writeLog("embedded core config reloaded")
			}
		}
		select {
		case request := <-requests:
			if request.Cmd == svc.Stop || request.Cmd == svc.Shutdown {
				writeLog("embedded core service stop received")
				return
			}
		case <-time.After(time.Second):
		}
	}
}
