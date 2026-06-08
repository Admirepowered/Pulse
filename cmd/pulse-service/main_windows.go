//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const (
	serviceName    = "PulseStartupService"
	configFileName = "pulse-startup-service.json"
	logFileName    = "pulse-startup-service.log"
)

type serviceConfig struct {
	Executable       string   `json:"executable"`
	WorkingDirectory string   `json:"workingDirectory"`
	Arguments        []string `json:"arguments"`
	Daemon           bool     `json:"daemon"`
	StopSignal       string   `json:"stopSignal"`
	UpdatedAt        int64    `json:"updatedAt"`
}

type pulseService struct{}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "run" {
		process, _, err := launchConfiguredPulse()
		if err != nil {
			writeLog("manual launch failed: " + err.Error())
			os.Exit(1)
		}
		windows.CloseHandle(process)
		return
	}
	if err := svc.Run(serviceName, pulseService{}); err != nil {
		writeLog("service run failed: " + err.Error())
	}
}

func (pulseService) Execute(args []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	lastError := ""
	for {
		process, config, err := launchConfiguredPulse()
		if err == nil {
			writeLog("launch requested")
			if !config.Daemon {
				windows.CloseHandle(process)
				changes <- svc.Status{State: svc.StopPending}
				return false, 0
			}
			if shouldStop := waitForPulseProcess(process, config, requests); shouldStop {
				changes <- svc.Status{State: svc.StopPending}
				return false, 0
			}
			lastError = ""
			time.Sleep(time.Second)
		} else if message := err.Error(); message != lastError {
			writeLog("launch failed: " + message)
			lastError = message
			if shouldStop := waitForRetry(requests, 2*time.Second); shouldStop {
				changes <- svc.Status{State: svc.StopPending}
				return false, 0
			}
		}
	}
}

func launchConfiguredPulse() (windows.Handle, serviceConfig, error) {
	config, err := readConfig()
	if err != nil {
		return 0, config, err
	}
	if strings.TrimSpace(config.Executable) == "" {
		return 0, config, fmt.Errorf("missing executable in %s", configFileName)
	}
	if _, err := os.Stat(config.Executable); err != nil {
		return 0, config, err
	}
	workingDirectory := config.WorkingDirectory
	if strings.TrimSpace(workingDirectory) == "" {
		workingDirectory = filepath.Dir(config.Executable)
	}
	process, err := createProcessInActiveSession(config.Executable, workingDirectory, config.Arguments)
	return process, config, err
}

func readConfig() (serviceConfig, error) {
	executable, err := os.Executable()
	if err != nil {
		return serviceConfig{}, err
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(executable), configFileName))
	if err != nil {
		return serviceConfig{}, err
	}
	var config serviceConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return serviceConfig{}, err
	}
	return config, nil
}

func createProcessInActiveSession(executable, workingDirectory string, args []string) (windows.Handle, error) {
	sessionID := windows.WTSGetActiveConsoleSessionId()
	if sessionID == 0xffffffff {
		return 0, fmt.Errorf("no active console session")
	}

	var userToken windows.Token
	if err := windows.WTSQueryUserToken(sessionID, &userToken); err != nil {
		return 0, fmt.Errorf("query active user token: %w", err)
	}
	defer userToken.Close()

	var primaryToken windows.Token
	err := windows.DuplicateTokenEx(
		userToken,
		windows.MAXIMUM_ALLOWED,
		nil,
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&primaryToken,
	)
	if err != nil {
		return 0, fmt.Errorf("duplicate user token: %w", err)
	}
	defer primaryToken.Close()

	var environment *uint16
	if err := windows.CreateEnvironmentBlock(&environment, primaryToken, false); err != nil {
		return 0, fmt.Errorf("create user environment: %w", err)
	}
	defer windows.DestroyEnvironmentBlock(environment)

	commandLine, err := windows.UTF16PtrFromString(windowsCommandLine(executable, args))
	if err != nil {
		return 0, err
	}
	currentDirectory, err := windows.UTF16PtrFromString(workingDirectory)
	if err != nil {
		return 0, err
	}
	desktop, err := windows.UTF16PtrFromString(`winsta0\default`)
	if err != nil {
		return 0, err
	}

	startupInfo := windows.StartupInfo{
		Cb:         uint32(unsafe.Sizeof(windows.StartupInfo{})),
		Desktop:    desktop,
		Flags:      windows.STARTF_USESHOWWINDOW,
		ShowWindow: windows.SW_SHOWNORMAL,
	}
	var processInfo windows.ProcessInformation
	err = windows.CreateProcessAsUser(
		primaryToken,
		nil,
		commandLine,
		nil,
		nil,
		false,
		windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NEW_PROCESS_GROUP,
		environment,
		currentDirectory,
		&startupInfo,
		&processInfo,
	)
	if err != nil {
		return 0, fmt.Errorf("create pulse process: %w", err)
	}
	windows.CloseHandle(processInfo.Thread)
	return processInfo.Process, nil
}

func waitForPulseProcess(process windows.Handle, config serviceConfig, requests <-chan svc.ChangeRequest) bool {
	defer windows.CloseHandle(process)
	stopMarker := signalModTime(config.StopSignal)
	for {
		event, err := windows.WaitForSingleObject(process, 1000)
		if err != nil {
			writeLog("process wait failed: " + err.Error())
			return false
		}
		if event == windows.WAIT_OBJECT_0 {
			if signalModTime(config.StopSignal).After(stopMarker) {
				writeLog("daemon stopped after user exit signal")
				return true
			}
			writeLog("daemon restarting Pulse after exit")
			return false
		}
		select {
		case request := <-requests:
			return request.Cmd == svc.Stop || request.Cmd == svc.Shutdown
		default:
		}
	}
}

func waitForRetry(requests <-chan svc.ChangeRequest, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case request := <-requests:
		return request.Cmd == svc.Stop || request.Cmd == svc.Shutdown
	case <-timer.C:
		return false
	}
}

func signalModTime(path string) time.Time {
	if strings.TrimSpace(path) == "" {
		return time.Time{}
	}
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

func windowsCommandLine(executable string, args []string) string {
	parts := []string{quoteWindowsArg(executable)}
	for _, arg := range args {
		parts = append(parts, quoteWindowsArg(arg))
	}
	return strings.Join(parts, " ")
}

func quoteWindowsArg(value string) string {
	if value == "" {
		return `""`
	}
	if !strings.ContainsAny(value, " \t\n\v\"") {
		return value
	}
	var builder strings.Builder
	builder.WriteByte('"')
	backslashes := 0
	for _, char := range value {
		switch char {
		case '\\':
			backslashes++
		case '"':
			builder.WriteString(strings.Repeat(`\`, backslashes*2+1))
			builder.WriteRune(char)
			backslashes = 0
		default:
			if backslashes > 0 {
				builder.WriteString(strings.Repeat(`\`, backslashes))
				backslashes = 0
			}
			builder.WriteRune(char)
		}
	}
	if backslashes > 0 {
		builder.WriteString(strings.Repeat(`\`, backslashes*2))
	}
	builder.WriteByte('"')
	return builder.String()
}

func writeLog(message string) {
	executable, err := os.Executable()
	if err != nil {
		return
	}
	line := time.Now().Format(time.RFC3339) + " " + message + "\n"
	path := filepath.Join(filepath.Dir(executable), logFileName)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = file.WriteString(line)
}
