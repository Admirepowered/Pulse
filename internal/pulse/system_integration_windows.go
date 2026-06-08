//go:build windows

package pulse

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	runKeyPath              = `Software\Microsoft\Windows\CurrentVersion\Run`
	internetSettingsKeyPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	startupValueName        = "Pulse"
	startupTaskName         = "Pulse"
	clashURLProtocolKeyPath = `Software\Classes\clash`
)

func setAutoStart(enabled bool) error {
	if err := deleteRunStartupValue(); err != nil {
		return err
	}
	if !enabled {
		return deleteElevatedStartupTask()
	}
	if !isProcessElevated() {
		return fmt.Errorf("开机启动需要管理员权限以注册最高权限启动任务，请以管理员身份重新启动 Pulse 后再开启")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	taskCommand := fmt.Sprintf(`"%s"`, executable)
	cmd := exec.Command("schtasks.exe", "/Create", "/F", "/TN", startupTaskName, "/SC", "ONLOGON", "/RL", "HIGHEST", "/TR", taskCommand)
	setCoreProcessOptions(cmd)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("register elevated startup task failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func deleteRunStartupValue() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	if err := key.DeleteValue(startupValueName); err != nil && err != registry.ErrNotExist {
		return err
	}
	return nil
}

func deleteElevatedStartupTask() error {
	cmd := exec.Command("schtasks.exe", "/Delete", "/F", "/TN", startupTaskName)
	setCoreProcessOptions(cmd)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	text := strings.ToLower(string(output))
	if strings.Contains(text, "cannot find") || strings.Contains(text, "找不到") || strings.Contains(text, "不存在") {
		return nil
	}
	return fmt.Errorf("delete elevated startup task failed: %w: %s", err, strings.TrimSpace(string(output)))
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
	directory := filepathForShellExecute(executable)
	script, err := writeAdminRelaunchScript(executable, directory, os.Args[1:])
	if err != nil {
		return err
	}
	cmd := exec.Command("cmd.exe", "/C", "start", "", "/MIN", script)
	setCoreProcessOptions(cmd)
	return cmd.Start()
}

func writeAdminRelaunchScript(executable, directory string, args []string) (string, error) {
	file, err := os.CreateTemp("", "pulse-admin-relaunch-*.cmd")
	if err != nil {
		return "", err
	}
	defer file.Close()
	powerShellCommand := adminRelaunchPowerShellCommand(executable, directory, args)
	content := fmt.Sprintf(
		`@echo off
setlocal
taskkill /PID %d /F >nul 2>nul
:wait_process
tasklist /FI "PID eq %d" | find "%d" >nul 2>nul
if not errorlevel 1 (
    timeout /t 1 /nobreak >nul
    goto wait_process
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "%s"
start "" /b cmd.exe /c "timeout /t 2 /nobreak >nul & del ""%%~f0"" >nul 2>nul"
`,
		os.Getpid(),
		os.Getpid(),
		os.Getpid(),
		escapeBatchPercent(powerShellCommand),
	)
	if _, err := file.WriteString(content); err != nil {
		return "", err
	}
	return file.Name(), nil
}

func adminRelaunchPowerShellCommand(executable, directory string, args []string) string {
	if len(args) == 0 {
		return fmt.Sprintf(
			"Start-Process -FilePath %s -WorkingDirectory %s -Verb RunAs",
			powerShellString(executable),
			powerShellString(directory),
		)
	}
	return fmt.Sprintf(
		"Start-Process -FilePath %s -ArgumentList @(%s) -WorkingDirectory %s -Verb RunAs",
		powerShellString(executable),
		powerShellStringList(args),
		powerShellString(directory),
	)
}

func escapeBatchPercent(value string) string {
	return strings.ReplaceAll(value, "%", "%%")
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
