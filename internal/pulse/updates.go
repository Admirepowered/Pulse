package pulse

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
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
	replacement, err := prepareDownloadedUpdate(downloaded)
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	switch goruntime.GOOS {
	case "windows":
		return a.scheduleWindowsExecutableReplace(replacement, executable)
	default:
		return a.scheduleUnixExecutableReplace(replacement, executable)
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
	wantVariant := preferredUpdateVariant()
	var fallback releaseAsset
	fallbackPriority := 99
	for _, candidate := range release.Assets {
		name := strings.ToLower(candidate.Name)
		if !matchesRuntimeOS(name, wantOS) || !strings.Contains(name, wantArch) {
			continue
		}
		priority, ok := updateAssetPriority(name, wantVariant)
		if !ok {
			continue
		}
		if fallback.Name == "" || priority < fallbackPriority {
			fallback = releaseAsset{Name: candidate.Name, BrowserDownloadURL: candidate.BrowserDownloadURL}
			fallbackPriority = priority
		}
		if priority == 0 {
			return fallback
		}
	}
	return fallback
}

// preferredUpdateVariant returns the substring the running build wants
// in an update asset name. App-embedded wants "app-embedded",
// service-embedded wants "service-embedded", everything else has no
// preference (returns "").
func preferredUpdateVariant() string {
	if appHasEmbeddedCore() {
		return "app-embedded"
	}
	if serviceHelperHasEmbeddedCore() {
		return "service-embedded"
	}
	return ""
}

func matchesRuntimeOS(name string, wantOS string) bool {
	if strings.Contains(name, wantOS) {
		return true
	}
	return wantOS == "linux" && strings.Contains(name, "ubuntu")
}

func updateAssetPriority(name string, wantVariant string) (int, bool) {
	if strings.Contains(name, "installer") {
		return 0, false
	}
	// Strongest preference: an asset whose name contains the variant
	// tag for the running build. The .zip containing that variant is
	// what the user actually wants.
	if wantVariant != "" && strings.Contains(name, wantVariant) {
		return 0, true
	}
	switch goruntime.GOOS {
	case "windows":
		if strings.HasSuffix(name, ".exe") {
			return 0, true
		}
		if strings.HasSuffix(name, ".zip") {
			return 1, true
		}
	default:
		if !strings.Contains(filepath.Base(name), ".") {
			return 0, true
		}
		if strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".zip") {
			return 1, true
		}
	}
	return 0, false
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
	if latestBuild != 0 || currentBuild != 0 {
		return latestBuild > currentBuild
	}
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

func prepareDownloadedUpdate(source string) (string, error) {
	lower := strings.ToLower(source)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		return extractZipUpdate(source)
	case strings.HasSuffix(lower, ".tar.gz"):
		return extractTarGzUpdate(source)
	default:
		return source, nil
	}
}

func extractZipUpdate(source string) (string, error) {
	reader, err := zip.OpenReader(source)
	if err != nil {
		return "", err
	}
	defer reader.Close()
	targetDir, err := prepareUpdateExtractDir(source)
	if err != nil {
		return "", err
	}
	for _, file := range reader.File {
		if file.FileInfo().IsDir() || !matchesUpdateArchiveEntry(file.Name) {
			continue
		}
		in, err := file.Open()
		if err != nil {
			return "", err
		}
		outPath, err := writeUpdateArchiveEntry(targetDir, file.Name, in)
		_ = in.Close()
		if err != nil {
			return "", err
		}
		return outPath, nil
	}
	return "", fmt.Errorf("no matching executable found in %s", filepath.Base(source))
}

func extractTarGzUpdate(source string) (string, error) {
	file, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return "", err
	}
	defer gzipReader.Close()
	targetDir, err := prepareUpdateExtractDir(source)
	if err != nil {
		return "", err
	}
	reader := tar.NewReader(gzipReader)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		if header.FileInfo().IsDir() || !matchesUpdateArchiveEntry(header.Name) {
			continue
		}
		return writeUpdateArchiveEntry(targetDir, header.Name, reader)
	}
	return "", fmt.Errorf("no matching executable found in %s", filepath.Base(source))
}

func prepareUpdateExtractDir(source string) (string, error) {
	targetDir := filepath.Join(filepath.Dir(source), "extracted")
	if err := os.RemoveAll(targetDir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return "", err
	}
	return targetDir, nil
}

func writeUpdateArchiveEntry(targetDir string, entryName string, reader io.Reader) (string, error) {
	outPath := filepath.Join(targetDir, path.Base(strings.ReplaceAll(entryName, "\\", "/")))
	out, err := os.Create(outPath)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, reader); err != nil {
		_ = out.Close()
		_ = os.Remove(outPath)
		return "", err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(outPath)
		return "", err
	}
	if goruntime.GOOS != "windows" {
		_ = os.Chmod(outPath, 0o755)
	}
	return outPath, nil
}

func matchesUpdateArchiveEntry(name string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(name, "\\", "/"))
	base := path.Base(normalized)
	if base == "" || strings.HasPrefix(base, ".") {
		return false
	}
	switch goruntime.GOOS {
	case "windows":
		return strings.HasSuffix(base, ".exe") &&
			(strings.Contains(normalized, "windows") || base == "pulse.exe") &&
			(strings.Contains(normalized, goruntime.GOARCH) || base == "pulse.exe")
	case "darwin":
		return strings.Contains(normalized, ".app/contents/macos/") && !strings.Contains(base, ".")
	default:
		return !strings.Contains(base, ".") &&
			matchesRuntimeOS(normalized, goruntime.GOOS) &&
			strings.Contains(normalized, goruntime.GOARCH)
	}
}

func shellQuote(value string) string {
	return `'` + strings.ReplaceAll(value, `'`, `'\''`) + `'`
}
