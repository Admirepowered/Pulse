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
	configBytes, err := os.ReadFile(config.RuntimeConfig)
	if err != nil {
		return err
	}
	stopLogForwarder := startMihomoLogForwarder()
	defer stopLogForwarder()

	mihomoConstant.SetHomeDir(config.DataDir)
	mihomoConstant.SetConfig(config.RuntimeConfig)
	if err := mihomoConfig.Init(mihomoConstant.Path.HomeDir()); err != nil {
		return err
	}
	route.SetEmbedMode(true)
	controller := "127.0.0.1:9090"
	if parsed, err := url.Parse(config.ApiBase); err == nil && parsed.Host != "" {
		controller = parsed.Host
	}
	if err := hub.Parse(configBytes, hub.WithExternalController(controller), hub.WithSecret(config.Secret)); err != nil {
		return err
	}
	writeLog("embedded core started")
	waitForEmbeddedCoreStop(config, requests)
	route.ReCreateServer(&route.Config{})
	executor.Shutdown()
	writeLog("embedded core stopped")
	return nil
}

func startMihomoLogForwarder() func() {
	sub := mihomoLog.Subscribe()
	go func() {
		for event := range sub {
			writeLog("mihomo " + event.Type() + ": " + event.Payload)
		}
	}()
	return func() {
		mihomoLog.UnSubscribe(sub)
	}
}

func waitForEmbeddedCoreStop(config serviceConfig, requests <-chan svc.ChangeRequest) {
	stopMarker := signalModTime(config.StopSignal)
	for {
		if signalModTime(config.StopSignal).After(stopMarker) {
			writeLog("embedded core stop signal received")
			return
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
