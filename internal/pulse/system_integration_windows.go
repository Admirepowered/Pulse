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
	_ = deleteElevatedStartupTask()
	if !enabled {
		return deleteRunStartupValue()
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	key, _, err := registry.CreateKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.SetStringValue(startupValueName, quoteWindowsArg(executable))
}

func setElevatedAutoStart(enabled bool) error {
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
	return relaunchAsAdministratorWithArgs(nil)
}

func relaunchAsAdministratorWithArgs(extraArgs []string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	directory := filepathForShellExecute(executable)
	args := append([]string{}, os.Args[1:]...)
	if len(extraArgs) > 0 {
		args = append(args, extraArgs...)
	}
	currentPid := os.Getpid()
	script := buildAdminRelaunchScript(executable, directory, args, currentPid)
	scriptFile, err := os.CreateTemp("", "pulse-admin-relaunch-*.ps1")
	if err != nil {
		return err
	}
	scriptPath := scriptFile.Name()
	if _, err := scriptFile.WriteString(script); err != nil {
		scriptFile.Close()
		os.Remove(scriptPath)
		return err
	}
	scriptFile.Close()
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", scriptPath)
	setCoreProcessOptions(cmd)
	return cmd.Start()
}

func buildAdminRelaunchScript(executable, directory string, args []string, currentPid int) string {
	argsLiteral := powerShellStringList(args)
	argsLine := ""
	if len(args) > 0 {
		argsLine = fmt.Sprintf("$args = @(%s)\n", argsLiteral)
	}
	return fmt.Sprintf(
		`$ErrorActionPreference = 'SilentlyContinue'
$exe = %s
$dir = %s
%s$currentPid = %d
# Give the calling Go process a moment to return its Wails response.
Start-Sleep -Milliseconds 500
# Stop the non-elevated instance so the elevated one can take over.
Stop-Process -Id $currentPid -Force -ErrorAction SilentlyContinue
# Trigger the UAC prompt and start the elevated instance.
Start-Process -FilePath $exe -ArgumentList $args -WorkingDirectory $dir -Verb RunAs
# Give the new process time to load before we delete this script.
Start-Sleep -Seconds 2
Remove-Item -Path $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
`,
		powerShellString(executable),
		powerShellString(directory),
		argsLine,
		currentPid,
	)
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
