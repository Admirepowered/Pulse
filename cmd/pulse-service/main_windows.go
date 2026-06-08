//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const (
	defaultServiceName = "PulseStartupService"
	defaultConfigFile  = "pulse-startup-service.json"
	logFileName        = "pulse-startup-service.log"
)

type serviceConfig struct {
	Executable       string   `json:"executable"`
	WorkingDirectory string   `json:"workingDirectory"`
	Arguments        []string `json:"arguments"`
	Daemon           bool     `json:"daemon"`
	StopSignal       string   `json:"stopSignal"`
	UserSession      bool     `json:"userSession"`
	EmbeddedCore     bool     `json:"embeddedCore"`
	DataDir          string   `json:"dataDir"`
	RuntimeConfig    string   `json:"runtimeConfig"`
	ApiBase          string   `json:"apiBase"`
	Secret           string   `json:"secret"`
	UpdatedAt        int64    `json:"updatedAt"`
}

type pulseService struct {
	configFile string
}

type runtimeOptions struct {
	serviceName string
	configFile  string
	manualRun   bool
}

func main() {
	options := parseRuntimeOptions(os.Args[1:])
	if options.manualRun {
		config, err := readConfig(options.configFile)
		if err != nil {
			writeLog("manual config read failed: " + err.Error())
			os.Exit(1)
		}
		if config.EmbeddedCore {
			if err := runEmbeddedCore(config, make(chan svc.ChangeRequest)); err != nil {
				writeLog("manual embedded core failed: " + err.Error())
				os.Exit(1)
			}
			return
		}
		process, config, err := launchConfiguredProcess(options.configFile)
		if err != nil {
			writeLog("manual launch failed: " + err.Error())
			os.Exit(1)
		}
		if config.Daemon {
			waitForPulseProcess(process, config, nil)
		} else {
			process.Close()
		}
		return
	}
	if err := svc.Run(options.serviceName, pulseService{configFile: options.configFile}); err != nil {
		writeLog("service run failed: " + err.Error())
	}
}

func (s pulseService) Execute(args []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	lastError := ""
	for {
		config, err := readConfig(s.configFile)
		if err == nil && config.EmbeddedCore {
			if err := runEmbeddedCore(config, requests); err != nil {
				if message := err.Error(); message != lastError {
					writeLog("embedded core failed: " + message)
					lastError = message
				}
				if shouldStop := waitForRetry(requests, 2*time.Second); shouldStop {
					changes <- svc.Status{State: svc.StopPending}
					return false, 0
				}
				continue
			}
			changes <- svc.Status{State: svc.StopPending}
			return false, 0
		}
		process, config, err := launchConfiguredProcess(s.configFile)
		if err == nil {
			writeLog("launch requested")
			if !config.Daemon {
				process.Close()
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

func parseRuntimeOptions(args []string) runtimeOptions {
	options := runtimeOptions{serviceName: defaultServiceName, configFile: defaultConfigFile}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "run":
			options.manualRun = true
		case arg == "--service-name" && i+1 < len(args):
			i++
			options.serviceName = args[i]
		case strings.HasPrefix(arg, "--service-name="):
			options.serviceName = strings.TrimPrefix(arg, "--service-name=")
		case arg == "--config" && i+1 < len(args):
			i++
			options.configFile = args[i]
		case strings.HasPrefix(arg, "--config="):
			options.configFile = strings.TrimPrefix(arg, "--config=")
		}
	}
	if strings.TrimSpace(options.serviceName) == "" {
		options.serviceName = defaultServiceName
	}
	if strings.TrimSpace(options.configFile) == "" {
		options.configFile = defaultConfigFile
	}
	return options
}

func launchConfiguredProcess(configFile string) (*launchedProcess, serviceConfig, error) {
	config, err := readConfig(configFile)
	if err != nil {
		return nil, config, err
	}
	if config.EmbeddedCore {
		return nil, config, fmt.Errorf("embedded core config cannot be launched as a child process")
	}
	if strings.TrimSpace(config.Executable) == "" {
		return nil, config, fmt.Errorf("missing executable in %s", configFile)
	}
	if _, err := os.Stat(config.Executable); err != nil {
		return nil, config, err
	}
	workingDirectory := config.WorkingDirectory
	if strings.TrimSpace(workingDirectory) == "" {
		workingDirectory = filepath.Dir(config.Executable)
	}
	if config.UserSession {
		process, err := createProcessInActiveSession(config.Executable, workingDirectory, config.Arguments)
		return &launchedProcess{handle: process}, config, err
	}
	process, err := createProcessInServiceSession(config.Executable, workingDirectory, config.Arguments)
	return process, config, err
}

func readConfig(configFile string) (serviceConfig, error) {
	executable, err := os.Executable()
	if err != nil {
		return serviceConfig{}, err
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(executable), configFile))
	if err != nil {
		return serviceConfig{}, err
	}
	var config serviceConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return serviceConfig{}, err
	}
	return config, nil
}

type launchedProcess struct {
	handle windows.Handle
	cmd    *exec.Cmd
	done   chan error
}

func (p *launchedProcess) Close() {
	if p == nil {
		return
	}
	if p.handle != 0 {
		windows.CloseHandle(p.handle)
		p.handle = 0
	}
}

func (p *launchedProcess) Kill() {
	if p == nil {
		return
	}
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		return
	}
	if p.handle != 0 {
		_ = windows.TerminateProcess(p.handle, 1)
	}
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

func createProcessInServiceSession(executable, workingDirectory string, args []string) (*launchedProcess, error) {
	cmd := exec.Command(executable, args...)
	cmd.Dir = workingDirectory
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP,
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	process := &launchedProcess{cmd: cmd, done: make(chan error, 1)}
	go func() {
		process.done <- cmd.Wait()
	}()
	return process, nil
}

func waitForPulseProcess(process *launchedProcess, config serviceConfig, requests <-chan svc.ChangeRequest) bool {
	defer process.Close()
	stopMarker := signalModTime(config.StopSignal)
	for {
		if signalModTime(config.StopSignal).After(stopMarker) {
			writeLog("daemon stop signal received")
			process.Kill()
			return true
		}
		if processExited(process, time.Second) {
			if signalModTime(config.StopSignal).After(stopMarker) {
				writeLog("daemon stopped after user exit signal")
				return true
			}
			writeLog("daemon restarting process after exit")
			return false
		}
		select {
		case request := <-requests:
			if request.Cmd == svc.Stop || request.Cmd == svc.Shutdown {
				process.Kill()
				return true
			}
		default:
		}
	}
}

func processExited(process *launchedProcess, timeout time.Duration) bool {
	if process.cmd != nil {
		select {
		case <-process.done:
			return true
		case <-time.After(timeout):
			return false
		}
	}
	event, err := windows.WaitForSingleObject(process.handle, uint32(timeout/time.Millisecond))
	if err != nil {
		writeLog("process wait failed: " + err.Error())
		return true
	}
	return event == windows.WAIT_OBJECT_0
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
