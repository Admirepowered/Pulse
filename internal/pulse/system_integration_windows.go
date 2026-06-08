//go:build windows

package pulse

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unicode/utf16"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	runKeyPath              = `Software\Microsoft\Windows\CurrentVersion\Run`
	internetSettingsKeyPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	startupValueName        = "Pulse"
	clashURLProtocolKeyPath = `Software\Classes\clash`
	adminRelaunchArg        = "--pulse-admin-relaunch"
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

func registerURLProtocol() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	key, _, err := registry.CreateKey(registry.CURRENT_USER, clashURLProtocolKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	if err := key.SetStringValue("", "URL:clash Protocol"); err != nil {
		_ = key.Close()
		return err
	}
	if err := key.SetStringValue("URL Protocol", ""); err != nil {
		_ = key.Close()
		return err
	}
	if err := key.Close(); err != nil {
		return err
	}
	commandKey, _, err := registry.CreateKey(registry.CURRENT_USER, clashURLProtocolKeyPath+`\shell\open\command`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer commandKey.Close()
	return commandKey.SetStringValue("", quoteWindowsArg(executable)+" \"%1\"")
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

func isProcessElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func relaunchAsAdministrator() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	args := append([]string{adminRelaunchArg}, os.Args[1:]...)
	directory := filepathForShellExecute(executable)
	script := fmt.Sprintf(
		"$ErrorActionPreference='SilentlyContinue'; Wait-Process -Id %d -Timeout 15; Start-Process -FilePath %s -ArgumentList @(%s) -Verb RunAs -WorkingDirectory %s",
		os.Getpid(),
		powerShellString(executable),
		powerShellStringList(args),
		powerShellString(directory),
	)
	cmd := exec.Command("powershell.exe", "-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand", powerShellEncodedCommand(script))
	setCoreProcessOptions(cmd)
	return cmd.Start()
}

func filepathForShellExecute(executable string) string {
	if executable == "" {
		return ""
	}
	lastSlash := strings.LastIndexAny(executable, `\/`)
	if lastSlash < 0 {
		return ""
	}
	return executable[:lastSlash]
}

func quoteWindowsArg(value string) string {
	if value == "" || (strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`)) {
		return value
	}
	return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}

func powerShellString(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func powerShellStringList(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, powerShellString(value))
	}
	return strings.Join(quoted, ",")
}

func powerShellEncodedCommand(script string) string {
	wide := utf16.Encode([]rune(script))
	data := make([]byte, len(wide)*2)
	for i, value := range wide {
		binary.LittleEndian.PutUint16(data[i*2:], value)
	}
	return base64.StdEncoding.EncodeToString(data)
}
