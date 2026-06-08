//go:build windows && !pulse_service_embed_mihomo

package main

import (
	"errors"

	"golang.org/x/sys/windows/svc"
)

func runEmbeddedCore(config serviceConfig, requests <-chan svc.ChangeRequest) error {
	return errors.New("PulseStartupService was built without embedded mihomo core")
}
