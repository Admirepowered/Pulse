//go:build windows && !pulse_embed_mihomo

package pulse

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
)

func ensureStartupServiceExecutable(dataDir string) (string, error) {
	if dataDir == "" {
		return "", errors.New("data directory is not initialized")
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return "", err
	}
	data, err := startupServiceAssets.ReadFile("assets/" + startupServiceExecutable)
	if err != nil {
		return "", errors.New("Windows 服务 helper 没有嵌入到当前程序，请先通过 make build-windows-service-mihomo 构建")
	}
	if len(data) < 2 || data[0] != 'M' || data[1] != 'Z' {
		return "", errors.New("Windows 服务 helper 不是有效的 PE 程序，请重新执行 make build-windows-service-mihomo")
	}
	servicePath := filepath.Join(dataDir, startupServiceExecutable)
	current, err := os.ReadFile(servicePath)
	if err == nil && bytes.Equal(current, data) {
		_ = writeStartupServiceBuildNumber(dataDir)
		return servicePath, nil
	}
	if err := os.WriteFile(servicePath, data, 0o755); err != nil {
		return "", err
	}
	_ = writeStartupServiceBuildNumber(dataDir)
	return servicePath, nil
}
