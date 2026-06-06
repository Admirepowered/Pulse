//go:build windows

package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

const (
	runKeyPath              = `Software\Microsoft\Windows\CurrentVersion\Run`
	internetSettingsKeyPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	startupValueName        = "Pulse"
)

func setAutoStart(enabled bool) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	if !enabled {
		if err := key.DeleteValue(startupValueName); err != nil && err != registry.ErrNotExist {
			return err
		}
		return nil
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	return key.SetStringValue(startupValueName, quoteWindowsArg(executable))
}

func configureSystemProxy(settings Settings, enabled bool) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	if !enabled {
		if err := key.SetDWordValue("ProxyEnable", 0); err != nil {
			return err
		}
		notifyProxySettingsChanged()
		return nil
	}
	port := settings.MixedPort
	if port <= 0 {
		port = defaultSettings().MixedPort
	}
	server := fmt.Sprintf("127.0.0.1:%d", port)
	if err := key.SetDWordValue("ProxyEnable", 1); err != nil {
		return err
	}
	if err := key.SetStringValue("ProxyServer", server); err != nil {
		return err
	}
	if err := key.SetStringValue("ProxyOverride", "<local>"); err != nil {
		return err
	}
	notifyProxySettingsChanged()
	return nil
}

func notifyProxySettingsChanged() {
	wininet := syscall.NewLazyDLL("wininet.dll")
	internetSetOption := wininet.NewProc("InternetSetOptionW")
	const (
		internetOptionRefresh         = 37
		internetOptionSettingsChanged = 39
	)
	internetSetOption.Call(0, internetOptionSettingsChanged, 0, 0)
	internetSetOption.Call(0, internetOptionRefresh, 0, 0)
}

func quoteWindowsArg(value string) string {
	if value == "" || (strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`)) {
		return value
	}
	return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}
