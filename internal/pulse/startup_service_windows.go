//go:build windows

package pulse

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	startupServiceName        = "PulseStartupService"
	startupServiceDisplayName = "Pulse Startup Service"
	startupServiceDescription = "Starts Pulse for the active desktop user at boot."
	startupServiceExecutable  = "PulseStartupService.exe"
	startupServiceConfigFile  = "pulse-startup-service.json"
)

type startupServiceConfig struct {
	Executable       string   `json:"executable"`
	WorkingDirectory string   `json:"workingDirectory"`
	Arguments        []string `json:"arguments"`
	Daemon           bool     `json:"daemon"`
	StopSignal       string   `json:"stopSignal"`
	UpdatedAt        int64    `json:"updatedAt"`
}

func syncStartupServicePayload(dataDir string, settings Settings) error {
	if dataDir == "" {
		return errors.New("data directory is not initialized")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	servicePath, err := ensureStartupServiceExecutable(dataDir)
	if err != nil {
		return err
	}
	config := startupServiceConfig{
		Executable:       executable,
		WorkingDirectory: filepath.Dir(executable),
		Arguments:        []string{"--start-hidden"},
		Daemon:           settings.AutoStartServiceDaemon,
		StopSignal:       filepath.Join(dataDir, "pulse-service-stop.signal"),
		UpdatedAt:        time.Now().Unix(),
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(servicePath), startupServiceConfigFile), data, 0o644); err != nil {
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
	servicePath, err := ensureStartupServiceExecutable(dataDir)
	if err != nil {
		return err
	}
	if err := syncStartupServicePayload(dataDir, settings); err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect service manager: %w", err)
	}
	defer manager.Disconnect()

	config := mgr.Config{
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:        mgr.StartAutomatic,
		ErrorControl:     mgr.ErrorNormal,
		DisplayName:      startupServiceDisplayName,
		Description:      startupServiceDescription,
		BinaryPathName:   servicePath,
		DelayedAutoStart: false,
	}
	service, err := manager.OpenService(startupServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		service, err = manager.CreateService(startupServiceName, servicePath, config)
	}
	if err != nil {
		return fmt.Errorf("open or create startup service: %w", err)
	}
	defer service.Close()
	if err := service.UpdateConfig(config); err != nil {
		return fmt.Errorf("update startup service: %w", err)
	}
	return nil
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
	service, err := manager.OpenService(startupServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return removeStartupServiceFiles(dataDir)
	}
	if err != nil {
		return fmt.Errorf("open startup service: %w", err)
	}
	defer service.Close()
	if _, err := service.Control(svc.Stop); err != nil &&
		!errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return fmt.Errorf("stop startup service: %w", err)
	}
	if err := service.Delete(); err != nil {
		return fmt.Errorf("delete startup service: %w", err)
	}
	return removeStartupServiceFiles(dataDir)
}

func ensureStartupServiceExecutable(dataDir string) (string, error) {
	if dataDir == "" {
		return "", errors.New("data directory is not initialized")
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return "", err
	}
	data, err := startupServiceAssets.ReadFile("assets/" + startupServiceExecutable)
	if err != nil {
		return "", errors.New("Windows 服务 helper 没有嵌入到当前程序，请先通过 make build-windows 构建")
	}
	if len(data) < 2 || data[0] != 'M' || data[1] != 'Z' {
		return "", errors.New("Windows 服务 helper 不是有效的 PE 程序，请重新执行 make build-windows")
	}
	servicePath := filepath.Join(dataDir, startupServiceExecutable)
	current, err := os.ReadFile(servicePath)
	if err == nil && bytes.Equal(current, data) {
		return servicePath, nil
	}
	if err := os.WriteFile(servicePath, data, 0o755); err != nil {
		return "", err
	}
	return servicePath, nil
}

func removeStartupServiceFiles(dataDir string) error {
	if dataDir == "" {
		return nil
	}
	servicePath := filepath.Join(dataDir, startupServiceExecutable)
	configPath := filepath.Join(dataDir, startupServiceConfigFile)
	if err := os.Remove(servicePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(configPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
