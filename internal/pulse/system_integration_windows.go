//go:build windows

package pulse

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
	server := fmt.Sprintf("http=127.0.0.1:%d;https=127.0.0.1:%d;socks=127.0.0.1:%d", port, port, port)
	if err := key.SetDWordValue("ProxyEnable", 1); err != nil {
		return err
	}
	if err := key.SetStringValue("ProxyServer", server); err != nil {
		return err
	}
	if err := key.DeleteValue("AutoConfigURL"); err != nil && err != registry.ErrNotExist {
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

func systemProxyState() string {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return "read failed: " + err.Error()
	}
	defer key.Close()
	enabled, _, err := key.GetIntegerValue("ProxyEnable")
	if err != nil {
		return "ProxyEnable read failed: " + err.Error()
	}
	server, _, _ := key.GetStringValue("ProxyServer")
	override, _, _ := key.GetStringValue("ProxyOverride")
	autoConfig, _, _ := key.GetStringValue("AutoConfigURL")
	return fmt.Sprintf("ProxyEnable=%d ProxyServer=%q ProxyOverride=%q AutoConfigURL=%q", enabled, server, override, autoConfig)
}

func quoteWindowsArg(value string) string {
	if value == "" || (strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`)) {
		return value
	}
	return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}
