package pulse

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	goruntime "runtime"
	"strconv"
	"strings"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

const latestReleaseURL = "https://api.github.com/repos/Admirepowered/Pulse/releases/latest"

type UpdateInfo struct {
	CurrentVersion string `json:"currentVersion"`
	LatestVersion  string `json:"latestVersion"`
	Available      bool   `json:"available"`
	URL            string `json:"url"`
	AssetName      string `json:"assetName"`
	Message        string `json:"message"`
}

type githubRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

type releaseAsset struct {
	Name               string
	BrowserDownloadURL string
}

func (a *App) CheckForUpdates() (UpdateInfo, error) {
	release, err := a.fetchLatestRelease()
	if err != nil {
		return UpdateInfo{CurrentVersion: AppVersion, Message: err.Error()}, err
	}
	asset := pickUpdateAsset(release)
	latest := updateVersionFromAsset(asset.Name, release.TagName)
	info := UpdateInfo{
		CurrentVersion: AppVersion,
		LatestVersion:  latest,
		Available:      versionGreater(latest, AppVersion),
		URL:            release.HTMLURL,
		AssetName:      asset.Name,
	}
	if asset.BrowserDownloadURL != "" {
		info.URL = asset.BrowserDownloadURL
	}
	if !info.Available {
		info.Message = "Already up to date"
	} else if info.AssetName == "" {
		info.Message = "Update available, but no matching executable asset was found"
	} else {
		info.Message = "Update available"
	}
	return info, nil
}

func (a *App) ApplyUpdate() error {
	info, err := a.CheckForUpdates()
	if err != nil {
		return err
	}
	if !info.Available {
		return errors.New("already up to date")
	}
	if info.AssetName == "" || info.URL == "" {
		return errors.New("no matching executable update asset")
	}
	downloaded, err := a.downloadUpdateAsset(info)
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	switch goruntime.GOOS {
	case "windows":
		return a.scheduleWindowsExecutableReplace(downloaded, executable)
	default:
		return a.scheduleUnixExecutableReplace(downloaded, executable)
	}
}

func (a *App) downloadUpdateAsset(info UpdateInfo) (string, error) {
	targetDir := filepath.Join(a.dataDir, "updates", strings.TrimPrefix(info.LatestVersion, "v"))
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return "", err
	}
	targetPath := filepath.Join(targetDir, info.AssetName)
	if err := a.downloadReleaseAsset(info.URL, targetPath); err != nil {
		return "", err
	}
	a.appendLog("info", "update downloaded: "+targetPath)
	return targetPath, nil
}

func (a *App) fetchLatestRelease() (githubRelease, error) {
	resp, err := a.githubRequest(http.MethodGet, latestReleaseURL, nil, map[string]string{"Accept": "application/vnd.github+json"})
	if err != nil {
		return githubRelease{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return githubRelease{}, fmt.Errorf("release API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return githubRelease{}, err
	}
	if release.TagName == "" {
		return githubRelease{}, errors.New("release API returned no tag")
	}
	return release, nil
}

func (a *App) downloadReleaseAsset(source string, target string) error {
	resp, err := a.githubRequest(http.MethodGet, source, nil, map[string]string{"Accept": "application/octet-stream,*/*"})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("download update returned HTTP %d", resp.StatusCode)
	}
	tempPath := target + ".part"
	out, err := os.Create(tempPath)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		_ = out.Close()
		_ = os.Remove(tempPath)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	if goruntime.GOOS != "windows" {
		_ = os.Chmod(tempPath, 0o755)
	}
	return os.Rename(tempPath, target)
}

func (a *App) scheduleWindowsExecutableReplace(downloaded string, executable string) error {
	scriptPath := filepath.Join(a.dataDir, "updates", "apply-update.ps1")
	script := fmt.Sprintf(`$ErrorActionPreference = "Stop"
$pidToWait = %d
$source = %q
$target = %q
Wait-Process -Id $pidToWait -ErrorAction SilentlyContinue
Copy-Item -LiteralPath $source -Destination $target -Force
Start-Process -FilePath $target
`, os.Getpid(), downloaded, executable)
	if err := os.WriteFile(scriptPath, []byte(script), 0o644); err != nil {
		return err
	}
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scriptPath)
	setCoreProcessOptions(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	return a.quitForUpdate()
}

func (a *App) scheduleUnixExecutableReplace(downloaded string, executable string) error {
	scriptPath := filepath.Join(a.dataDir, "updates", "apply-update.sh")
	script := fmt.Sprintf(`#!/bin/sh
set -e
pid="%d"
source=%s
target=%s
while kill -0 "$pid" 2>/dev/null; do sleep 0.2; done
cp "$source" "$target"
chmod +x "$target"
"$target" >/dev/null 2>&1 &
`, os.Getpid(), shellQuote(downloaded), shellQuote(executable))
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		return err
	}
	cmd := exec.Command("sh", scriptPath)
	if err := cmd.Start(); err != nil {
		return err
	}
	return a.quitForUpdate()
}

func (a *App) quitForUpdate() error {
	a.appendLog("info", "update apply scheduled")
	a.mu.Lock()
	a.forceQuit = true
	a.mu.Unlock()
	if a.ctx != nil {
		wailsruntime.Quit(a.ctx)
	}
	return nil
}

func pickUpdateAsset(release githubRelease) releaseAsset {
	wantOS := goruntime.GOOS
	wantArch := goruntime.GOARCH
	var fallback releaseAsset
	for _, candidate := range release.Assets {
		name := strings.ToLower(candidate.Name)
		if !matchesRuntimeOS(name, wantOS) || !strings.Contains(name, wantArch) {
			continue
		}
		if !isExecutableUpdateAsset(name) {
			continue
		}
		if fallback.Name == "" {
			fallback = releaseAsset{Name: candidate.Name, BrowserDownloadURL: candidate.BrowserDownloadURL}
		}
		if goruntime.GOOS == "windows" && strings.HasSuffix(name, ".exe") && !strings.Contains(name, "installer") {
			return releaseAsset{Name: candidate.Name, BrowserDownloadURL: candidate.BrowserDownloadURL}
		}
	}
	return fallback
}

func matchesRuntimeOS(name string, wantOS string) bool {
	if strings.Contains(name, wantOS) {
		return true
	}
	return wantOS == "linux" && strings.Contains(name, "ubuntu")
}

func isExecutableUpdateAsset(name string) bool {
	if strings.Contains(name, "installer") || strings.Contains(name, ".zip") || strings.Contains(name, ".tar.gz") {
		return false
	}
	switch goruntime.GOOS {
	case "windows":
		return strings.HasSuffix(name, ".exe")
	default:
		return !strings.Contains(filepath.Base(name), ".")
	}
}

func updateVersionFromAsset(assetName string, tagName string) string {
	name := strings.TrimSpace(assetName)
	if name != "" {
		matches := regexp.MustCompile(`(?i)^pulse-(.+?)-(windows|linux|darwin|macos)(?:-|$)`).FindStringSubmatch(name)
		if len(matches) > 1 {
			return matches[1]
		}
	}
	return strings.TrimSpace(tagName)
}

func versionGreater(latest string, current string) bool {
	latestBase, latestBuild := splitVersionAndBuild(latest)
	currentBase, currentBuild := splitVersionAndBuild(current)
	if latestBase != "" || currentBase != "" {
		if currentBase == "" {
			return latestBuild > currentBuild
		}
		if latestBase != currentBase {
			return versionBaseGreater(latestBase, currentBase)
		}
		if latestBuild != currentBuild {
			return latestBuild > currentBuild
		}
		return false
	}
	if latestBuild != 0 || currentBuild != 0 {
		return latestBuild > currentBuild
	}
	return versionBaseGreater(latest, current)
}

func versionBaseGreater(latest string, current string) bool {
	l := parseVersionParts(latest)
	c := parseVersionParts(current)
	for i := 0; i < len(l) || i < len(c); i++ {
		var lv, cv int
		if i < len(l) {
			lv = l[i]
		}
		if i < len(c) {
			cv = c[i]
		}
		if lv != cv {
			return lv > cv
		}
	}
	return false
}

func splitVersionAndBuild(value string) (string, int) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	parts := strings.Split(value, "-")
	base := strings.TrimSpace(parts[0])
	if strings.HasPrefix(strings.ToUpper(base), "P") {
		return "", parseBuildNumber(base)
	}
	for _, part := range parts[1:] {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(part)), "P") {
			return base, parseBuildNumber(part)
		}
	}
	return base, 0
}

func parseBuildNumber(value string) int {
	value = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(value)), "P")
	n, _ := strconv.Atoi(value)
	return n
}

func parseVersionParts(value string) []int {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	value = strings.TrimPrefix(value, "P")
	value = strings.Split(value, "-")[0]
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == '.' || r == '_' })
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		if n, err := strconv.Atoi(part); err == nil {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return []int{0}
	}
	return out
}

func shellQuote(value string) string {
	return `'` + strings.ReplaceAll(value, `'`, `'\''`) + `'`
}
