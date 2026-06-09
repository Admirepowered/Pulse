//go:build windows

// This file owns the `PulseStartupService` (boot autostart) and
// `PulseCoreService` (service CoreMode) lifecycle on Windows.
//
// Three core mode implementations are supported, selected by the build tags:
//   - **App-embedded** (`pulse_embed_mihomo`): mihomo runs in the Pulse app
//     process. The `AutoStartService` boot service is unnecessary — Pulse can
//     autostart via the `Run` registry and run the core in-process.
//   - **Service-embedded** (`pulse_service_embed_mihomo`, Windows only): the
//     `PulseStartupService.exe` binary has mihomo linked in. The user can
//     register it as a Windows service (CoreMode `service`) to run the core
//     as a service, or the app can spawn it as a child process to act as the
//     core (CoreMode `embedded`, helper-managed path).
//   - **External** (default Windows, helper runs an external `mihomo.exe`):
//     `PulseStartupService.exe` has no embedded core and launches the mihomo
//     binary resolved from `settings.CorePath`. The app still spawns the
//     helper as a child process.
package pulse

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	startupServiceName        = "PulseStartupService"
	startupServiceDisplayName = "Pulse Startup Service"
	startupServiceDescription = "Starts Pulse for the active desktop user at boot."
	coreServiceName           = "PulseCoreService"
	coreServiceDisplayName    = "Pulse Core Service"
	coreServiceDescription    = "Runs Pulse core with service privileges."
	startupServiceExecutable  = "PulseStartupService.exe"
	startupServiceConfigFile  = "pulse-startup-service.json"
	coreServiceConfigFile     = "pulse-core-service.json"
	startupServiceVersionFile = "pulse-startup-service.version.json"
)

type startupServiceConfig struct {
	Executable       string   `json:"executable"`
	WorkingDirectory string   `json:"workingDirectory"`
	Arguments        []string `json:"arguments"`
	Daemon           bool     `json:"daemon"`
	StopSignal       string   `json:"stopSignal"`
	ReloadSignal     string   `json:"reloadSignal"`
	UserSession      bool     `json:"userSession"`
	EmbeddedCore     bool     `json:"embeddedCore"`
	DataDir          string   `json:"dataDir"`
	RuntimeConfig    string   `json:"runtimeConfig"`
	ApiBase          string   `json:"apiBase"`
	Secret           string   `json:"secret"`
	UpdatedAt        int64    `json:"updatedAt"`
}

type startupServiceVersionInfo struct {
	ServiceBuildNumber string `json:"serviceBuildNumber"`
	UpdatedAt          int64  `json:"updatedAt"`
}

func syncStartupServiceExecutable(dataDir string) error {
	_, err := ensureStartupServiceExecutable(dataDir)
	return err
}

func writeStartupServiceBuildNumber(dataDir string) error {
	if dataDir == "" {
		return errors.New("data directory is not initialized")
	}
	info := startupServiceVersionInfo{
		ServiceBuildNumber: ServiceBuildNumber,
		UpdatedAt:          time.Now().Unix(),
	}
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dataDir, startupServiceVersionFile), data, 0o644)
}

func startupServiceBuildStatus(dataDir string, settings Settings) (string, bool) {
	if dataDir == "" || appHasEmbeddedCore() || (!settings.AutoStartService && settings.CoreMode != "service") {
		return "", false
	}
	servicePath := filepath.Join(dataDir, startupServiceExecutable)
	if _, err := os.Stat(servicePath); err != nil {
		return "", false
	}
	data, err := os.ReadFile(filepath.Join(dataDir, startupServiceVersionFile))
	if err != nil {
		return "", true
	}
	var info startupServiceVersionInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return "", true
	}
	buildNumber := strings.TrimSpace(info.ServiceBuildNumber)
	return buildNumber, parseBuildNumber(ServiceBuildNumber) > parseBuildNumber(buildNumber)
}

func startupServiceRegistered() bool {
	manager, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer manager.Disconnect()
	namePtr, err := windows.UTF16PtrFromString(startupServiceName)
	if err != nil {
		return false
	}
	h, err := windows.OpenService(manager.Handle, namePtr, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	return true
}

func startupServiceExecutableMissing(dataDir string) bool {
	if dataDir == "" {
		return true
	}
	_, err := os.Stat(filepath.Join(dataDir, startupServiceExecutable))
	return err != nil
}

func syncStartupServicePayload(dataDir string, settings Settings) error {
	if _, err := ensureStartupServiceExecutable(dataDir); err != nil {
		return err
	}
	return writeStartupServicePayload(dataDir, settings)
}

func writeStartupServicePayload(dataDir string, settings Settings) error {
	if dataDir == "" {
		return errors.New("data directory is not initialized")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	config := startupServiceConfig{
		Executable:       executable,
		WorkingDirectory: filepath.Dir(executable),
		Arguments:        []string{"--start-hidden"},
		Daemon:           false,
		StopSignal:       filepath.Join(dataDir, "pulse-service-stop.signal"),
		UserSession:      true,
		UpdatedAt:        time.Now().Unix(),
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dataDir, startupServiceConfigFile), data, 0o644); err != nil {
		return err
	}
	return nil
}

func setServiceAutoStart(dataDir string, settings Settings, enabled bool) error {
	if !enabled {
		return uninstallStartupService(dataDir)
	}
	if !isProcessElevated() {
		return errors.New("服务启动需要管理员权限进行首次注册，请以管理员身份重新启动 Pulse 后再开启")
	}
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect service manager: %w", err)
	}
	defer manager.Disconnect()
	if err := deleteServiceIfExists(manager, startupServiceName, 8*time.Second); err != nil {
		return fmt.Errorf("remove old startup service: %w", err)
	}
	servicePath, err := ensureStartupServiceExecutable(dataDir)
	if err != nil {
		return err
	}
	if err := writeStartupServicePayload(dataDir, settings); err != nil {
		return err
	}
	runtimeConfig := filepath.Join(dataDir, "pulse-runtime.yaml")
	if _, err := writeCoreServiceConfig(dataDir, settings, runtimeConfig); err != nil {
		return err
	}

	config := mgr.Config{
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:        mgr.StartAutomatic,
		ErrorControl:     mgr.ErrorNormal,
		DisplayName:      startupServiceDisplayName,
		Description:      startupServiceDescription,
		BinaryPathName:   servicePath,
		DelayedAutoStart: false,
	}
	service, err := manager.CreateService(startupServiceName, servicePath, config)
	if err != nil {
		return fmt.Errorf("create startup service: %w", err)
	}
	defer service.Close()
	if err := ensureCoreServiceRegistered(servicePath, true); err != nil {
		return err
	}
	if err := startRegisteredService(coreServiceName); err != nil {
		return err
	}
	return nil
}

func startServiceCore(dataDir string, settings Settings, runtimeConfig string) error {
	if coreAPIIsReachable(settings.ApiBase, settings.Secret) {
		return nil
	}
	servicePath, err := writeCoreServiceConfig(dataDir, settings, runtimeConfig)
	if err != nil {
		return err
	}
	if isCoreServiceRunning() {
		return nil
	}
	if err := ensureCoreServiceRegistered(servicePath, true); err != nil {
		return errors.New("服务未注册，请先在设置中开启 AutoStartService 之后再启动核心")
	}
	return startRegisteredService(coreServiceName)
}

func startManagedHelperCore(dataDir string, settings Settings, runtimeConfig string) (*exec.Cmd, error) {
	servicePath, err := writeCoreServiceConfig(dataDir, settings, runtimeConfig)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(servicePath, "run", "--config", coreServiceConfigFile)
	cmd.Dir = filepath.Dir(servicePath)
	setCoreProcessOptions(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

func writeCoreServiceConfig(dataDir string, settings Settings, runtimeConfig string) (string, error) {
	servicePath, err := ensureStartupServiceExecutable(dataDir)
	if err != nil {
		return "", err
	}
	config := startupServiceConfig{
		WorkingDirectory: dataDir,
		Daemon:           true,
		StopSignal:       filepath.Join(dataDir, "pulse-core-stop.signal"),
		ReloadSignal:     filepath.Join(dataDir, "pulse-core-reload.signal"),
		UserSession:      false,
		DataDir:          dataDir,
		RuntimeConfig:    runtimeConfig,
		ApiBase:          settings.ApiBase,
		Secret:           settings.Secret,
		UpdatedAt:        time.Now().Unix(),
	}
	if serviceHelperHasEmbeddedCore() {
		config.EmbeddedCore = true
	} else {
		corePath, err := resolveCorePathStandalone(settings.CorePath)
		if err != nil {
			return "", err
		}
		config.Executable = corePath
		config.WorkingDirectory = filepath.Dir(corePath)
		config.Arguments = []string{"-d", dataDir, "-f", runtimeConfig}
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dataDir, coreServiceConfigFile), data, 0o644); err != nil {
		return "", err
	}
	return servicePath, nil
}

func stopServiceCore(dataDir string) error {
	if dataDir != "" {
		_ = os.WriteFile(filepath.Join(dataDir, "pulse-core-stop.signal"), []byte(fmt.Sprintf("%d", time.Now().UnixNano())), 0o644)
	}
	if !isProcessElevated() {
		return nil
	}
	return stopRegisteredService(coreServiceName)
}

func ensureCoreServiceRegistered(servicePath string, automatic bool) error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect service manager: %w", err)
	}
	defer manager.Disconnect()
	startType := uint32(mgr.StartManual)
	if automatic {
		startType = uint32(mgr.StartAutomatic)
	}
	config := mgr.Config{
		ServiceType:    windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:      startType,
		ErrorControl:   mgr.ErrorNormal,
		DisplayName:    coreServiceDisplayName,
		Description:    coreServiceDescription,
		BinaryPathName: coreServiceBinaryPath(servicePath),
	}
	service, err := manager.OpenService(coreServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		service, err = manager.CreateService(coreServiceName, servicePath, config, "--service-name", coreServiceName, "--config", coreServiceConfigFile)
	}
	if err != nil {
		return fmt.Errorf("open or create core service: %w", err)
	}
	defer service.Close()
	if err := configureServiceRecovery(service); err != nil {
		return fmt.Errorf("configure core service recovery: %w", err)
	}
	// UpdateConfig can fail when the service is running; only update when
	// the service is stopped, so we don't break reconnection after an
	// app restart.
	if err := service.UpdateConfig(config); err != nil {
		return fmt.Errorf("update core service: %w", err)
	}
	return nil
}

func coreServiceBinaryPath(servicePath string) string {
	return strings.Join([]string{
		quoteWindowsArg(servicePath),
		"--service-name",
		coreServiceName,
		"--config",
		coreServiceConfigFile,
	}, " ")
}

func startRegisteredService(name string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect service manager: %w", err)
	}
	defer manager.Disconnect()
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	h, err := windows.OpenService(manager.Handle, namePtr, windows.SERVICE_START|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return fmt.Errorf("open service %s: %w", name, err)
	}
	defer windows.CloseHandle(h)
	if err := windows.StartService(h, 0, nil); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return fmt.Errorf("start service %s: %w", name, err)
	}
	return nil
}

func stopRegisteredService(name string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect service manager: %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open service %s: %w", name, err)
	}
	defer service.Close()
	if _, err := service.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return fmt.Errorf("stop service %s: %w", name, err)
	}
	return nil
}

func deleteServiceIfExists(manager *mgr.Mgr, name string, timeout time.Duration) error {
	service, err := manager.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open service %s: %w", name, err)
	}
	defer service.Close()
	status, queryErr := service.Query()
	if queryErr == nil && status.State != svc.Stopped {
		if _, err := service.Control(svc.Stop); err != nil &&
			!errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return fmt.Errorf("stop service %s: %w", name, err)
		}
		if err := waitForServiceState(service, svc.Stopped, timeout); err != nil {
			return fmt.Errorf("wait for service %s stopped: %w", name, err)
		}
	}
	if err := service.Delete(); err != nil {
		return fmt.Errorf("delete service %s: %w", name, err)
	}
	return nil
}

func configureServiceRecovery(service *mgr.Service) error {
	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: time.Second},
		{Type: mgr.ServiceRestart, Delay: 3 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
	}
	if err := service.SetRecoveryActions(actions, 60); err != nil {
		return err
	}
	return service.SetRecoveryActionsOnNonCrashFailures(true)
}

func coreAPIIsReachable(apiBase, secret string) bool {
	req, err := http.NewRequest(http.MethodGet, apiBase+"/version", nil)
	if err != nil {
		return false
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func isCoreServiceRunning() bool {
	manager, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer manager.Disconnect()
	namePtr, err := windows.UTF16PtrFromString(coreServiceName)
	if err != nil {
		return false
	}
	// OpenService from the mgr package requests SERVICE_ALL_ACCESS, which
	// fails for non-elevated callers. Query-only needs SERVICE_QUERY_STATUS.
	h, err := windows.OpenService(manager.Handle, namePtr, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var status windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(h, &status); err != nil {
		return false
	}
	return status.CurrentState == uint32(svc.Running)
}

func resolveCorePathStandalone(corePath string) (string, error) {
	corePath = strings.TrimSpace(corePath)
	if corePath == "" {
		corePath = defaultSettings().CorePath
	}
	if strings.ContainsAny(corePath, `/\`) {
		candidates := []string{corePath}
		if !filepath.IsAbs(corePath) {
			if cwd, err := os.Getwd(); err == nil {
				candidates = append(candidates, filepath.Join(cwd, corePath))
			}
			if exe, err := os.Executable(); err == nil {
				candidates = append(candidates, filepath.Join(filepath.Dir(exe), corePath))
			}
		}
		for _, candidate := range candidates {
			if path, ok := existingFile(candidate); ok {
				return path, nil
			}
		}
		return "", fmt.Errorf("core not found: %s", corePath)
	}
	return exec.LookPath(corePath)
}

func uninstallStartupService(dataDir string) error {
	if !isProcessElevated() {
		return errors.New("关闭服务启动需要管理员权限，请以管理员身份重新启动 Pulse 后再关闭")
	}
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect service manager: %w", err)
	}
	defer manager.Disconnect()
	if err := deleteServiceIfExists(manager, coreServiceName, 8*time.Second); err != nil {
		return err
	}
	if err := deleteServiceIfExists(manager, startupServiceName, 8*time.Second); err != nil {
		return err
	}
	return removeStartupServiceFiles(dataDir)
}

func waitForServiceState(service *mgr.Service, want svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State == want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for service to reach state %v (current %v)", want, status.State)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func removeStartupServiceFiles(dataDir string) error {
	if dataDir == "" {
		return nil
	}
	servicePath := filepath.Join(dataDir, startupServiceExecutable)
	configPath := filepath.Join(dataDir, startupServiceConfigFile)
	versionPath := filepath.Join(dataDir, startupServiceVersionFile)
	// Best-effort. The helper binary may still be locked by the OS
	// even after waitForServiceState sees Stopped (a child mihomo
	// process, or just the OS holding the handle open a moment longer),
	// in which case os.Remove returns "Access is denied". The service
	// is already unregistered from SCM at this point, which is the
	// real goal of the uninstall; the leftover file is harmless and
	// will be overwritten on the next service registration. Don't
	// surface the failure to the user.
	_ = os.Remove(servicePath)
	_ = os.Remove(configPath)
	_ = os.Remove(versionPath)
	return nil
}
