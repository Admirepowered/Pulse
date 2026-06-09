package pulse

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
	"gopkg.in/yaml.v3"
)

type App struct {
	ctx                  context.Context
	mu                   sync.Mutex
	dataDir              string
	storePath            string
	store                Store
	coreCmd              *exec.Cmd
	embeddedCoreRunning  bool
	serviceCoreRunning   bool
	embeddedLogSub       any
	startedAt            int64
	logLines             []LogLine
	geodataStatus        GeodataStatus
	geodataRunning       bool
	httpClient           *http.Client
	forceQuit            bool
	trayOnce             sync.Once
	trayMu               sync.Mutex
	trayReady            bool
	trayShowItem         *trayMenuItem
	trayCoreItem         *trayMenuItem
	trayStatusItem       *trayMenuItem
	trayModeMenu         *trayMenuItem
	trayRuleModeItem     *trayMenuItem
	trayGlobalModeItem   *trayMenuItem
	trayDirectModeItem   *trayMenuItem
	trayAllowLanItem     *trayMenuItem
	traySystemProxyItem  *trayMenuItem
	traySubProxyItem     *trayMenuItem
	trayAutoStartItem    *trayMenuItem
	trayProfilesMenu     *trayMenuItem
	trayProfileIDs       []string
	trayProfileItems     []*trayMenuItem
	trayNodesMenu        *trayMenuItem
	trayNodeStatusItem   *trayMenuItem
	trayNodeGroupNames   []string
	trayNodeNamesByGroup [][]string
	trayNodeGroupItems   []*trayMenuItem
	trayNodeItems        [][]*trayMenuItem
	trayRefreshItem      *trayMenuItem
	trayQuitItem         *trayMenuItem
	trayWndProc          uintptr
	trayPrevWndProc      uintptr
	trayLastLeftClick    int64
	showSignalPath       string
	lastShowSignalTime   time.Time
	connectionSamples    map[string]connectionSample
	closedConnections    []ConnectionRow
}

type connectionSample struct {
	Row ConnectionRow
	At  time.Time
}

const (
	tunAdminRequiredMessage = "TUN 模式需要管理员权限，请以管理员身份重新启动 Pulse"
)

type Store struct {
	ActiveProfileID string    `json:"activeProfileId"`
	Profiles        []Profile `json:"profiles"`
	Settings        Settings  `json:"settings"`
}

type Settings struct {
	CorePath               string         `json:"corePath"`
	CoreMode               string         `json:"coreMode"`
	ApiBase                string         `json:"apiBase"`
	Secret                 string         `json:"secret"`
	MixedPort              int            `json:"mixedPort"`
	AllowLan               bool           `json:"allowLan"`
	Mode                   string         `json:"mode"`
	LogLevel               string         `json:"logLevel"`
	TunEnabled             bool           `json:"tunEnabled"`
	TunInterface           string         `json:"tunInterface"`
	TunStack               string         `json:"tunStack"`
	TunAutoRoute           bool           `json:"tunAutoRoute"`
	TunAutoRedirect        bool           `json:"tunAutoRedirect"`
	TunAutoDetect          bool           `json:"tunAutoDetectInterface"`
	TunDNSHijack           []string       `json:"tunDNSHijack"`
	TunDevice              string         `json:"tunDevice"`
	TunMTU                 int            `json:"tunMTU"`
	TunStrictRoute         bool           `json:"tunStrictRoute"`
	TunGSO                 bool           `json:"tunGSO"`
	TunGSOMaxSize          int            `json:"tunGSOMaxSize"`
	TunInet6Address        string         `json:"tunInet6Address"`
	TunUDPTimeout          int            `json:"tunUDPTimeout"`
	TunIPRoute2Table       int            `json:"tunIPRoute2TableIndex"`
	TunIPRoute2Rule        int            `json:"tunIPRoute2RuleIndex"`
	TunEINAT               bool           `json:"tunEndpointIndependentNAT"`
	TunRouteSet            []string       `json:"tunRouteAddressSet"`
	TunRouteExcludeSet     []string       `json:"tunRouteExcludeAddressSet"`
	TunRouteAddress        []string       `json:"tunRouteAddress"`
	TunRouteExclude        []string       `json:"tunRouteExcludeAddress"`
	TunIncludeIF           []string       `json:"tunIncludeInterface"`
	TunExcludeIF           []string       `json:"tunExcludeInterface"`
	TunIncludeUID          []int          `json:"tunIncludeUID"`
	TunIncludeUIDRange     []string       `json:"tunIncludeUIDRange"`
	TunExcludeUID          []int          `json:"tunExcludeUID"`
	TunExcludeUIDRange     []string       `json:"tunExcludeUIDRange"`
	TunIncludeAndroid      []int          `json:"tunIncludeAndroidUser"`
	TunIncludePackage      []string       `json:"tunIncludePackage"`
	TunExcludePackage      []string       `json:"tunExcludePackage"`
	TunInet4Route          []string       `json:"tunInet4RouteAddress"`
	TunInet6Route          []string       `json:"tunInet6RouteAddress"`
	TunInet4RouteExclude   []string       `json:"tunInet4RouteExcludeAddress"`
	TunInet6RouteExclude   []string       `json:"tunInet6RouteExcludeAddress"`
	SystemProxy            bool           `json:"systemProxy"`
	DelayTestURL           string         `json:"delayTestUrl"`
	Language               string         `json:"language"`
	Theme                  string         `json:"theme"`
	AutoStart              bool           `json:"autoStart"`
	AutoStartService       bool           `json:"autoStartService"`
	AutoStartServiceDaemon bool           `json:"autoStartServiceDaemon"`
	AutoStartCore          bool           `json:"autoStartCore"`
	DisableUpdateCheck     bool           `json:"disableUpdateCheck"`
	CloseBehavior          string         `json:"closeBehavior"`
	SubscriptionProxy      bool           `json:"subscriptionProxy"`
	BackgroundPath         string         `json:"backgroundPath"`
	BackgroundBlur         int            `json:"backgroundBlur"`
	BackgroundOpacity      int            `json:"backgroundOpacity"`
	WebDAV                 WebDAVSettings `json:"webdav"`
}

type BackgroundImage struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type NetworkInterface struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"displayName"`
	Addresses   []string `json:"addresses"`
}

type WebDAVSettings struct {
	Enabled  bool   `json:"enabled"`
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Profile struct {
	ID           string           `json:"id"`
	Name         string           `json:"name"`
	Type         string           `json:"type"`
	Source       string           `json:"source"`
	Path         string           `json:"path"`
	UpdatedAt    int64            `json:"updatedAt"`
	Enabled      bool             `json:"enabled"`
	Subscription SubscriptionInfo `json:"subscription"`
}

type SubscriptionInfo struct {
	Upload         int64  `json:"upload"`
	Download       int64  `json:"download"`
	Total          int64  `json:"total"`
	Expire         int64  `json:"expire"`
	UpdateInterval int    `json:"updateInterval"`
	RawUserInfo    string `json:"rawUserInfo"`
	UpdatedAt      int64  `json:"updatedAt"`
}

type RuntimeState struct {
	Running                bool            `json:"running"`
	ApiReachable           bool            `json:"apiReachable"`
	CoreFound              bool            `json:"coreFound"`
	Version                string          `json:"version"`
	BuildNumber            string          `json:"buildNumber"`
	Platform               string          `json:"platform"`
	AppEmbeddedCore        bool            `json:"appEmbeddedCore"`
	ServiceEmbeddedCore    bool            `json:"serviceEmbeddedCore"`
	CoreModeImplementation string          `json:"coreModeImplementation"`
	StartedAt              int64           `json:"startedAt"`
	DataDir                string          `json:"dataDir"`
	ActiveProfile          string          `json:"activeProfile"`
	Profiles               []Profile       `json:"profiles"`
	Settings               Settings        `json:"settings"`
	Traffic                TrafficSnapshot `json:"traffic"`
	RecentLogs             []LogLine       `json:"recentLogs"`
	Geodata                GeodataStatus   `json:"geodata"`
}

type LogLine struct {
	Time    int64  `json:"time"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

type TrafficSnapshot struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

type ProxyGroup struct {
	Name  string      `json:"name"`
	Type  string      `json:"type"`
	Now   string      `json:"now"`
	Nodes []ProxyNode `json:"nodes"`
}

type ProxyNode struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Delay int    `json:"delay"`
	Alive bool   `json:"alive"`
}

type RuleRow struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Proxy   string `json:"proxy"`
}

type CustomRule struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Payload   string `json:"payload"`
	Proxy     string `json:"proxy"`
	NoResolve bool   `json:"noResolve"`
}

type ProviderRow struct {
	Name      string `json:"name"`
	Vehicle   string `json:"vehicle"`
	UpdatedAt string `json:"updatedAt"`
	Proxies   int    `json:"proxies"`
}

type ConnectionRow struct {
	ID            string `json:"id"`
	Network       string `json:"network"`
	Address       string `json:"address"`
	DestinationIP string `json:"destinationIp"`
	Source        string `json:"source"`
	Process       string `json:"process"`
	Rule          string `json:"rule"`
	Chains        string `json:"chains"`
	Upload        int64  `json:"upload"`
	Download      int64  `json:"download"`
	UploadSpeed   int64  `json:"uploadSpeed"`
	DownloadSpeed int64  `json:"downloadSpeed"`
	Start         string `json:"start"`
	ClosedAt      int64  `json:"closedAt"`
}

type ConnectionSnapshot struct {
	UploadTotal   int64           `json:"uploadTotal"`
	DownloadTotal int64           `json:"downloadTotal"`
	Memory        uint64          `json:"memory"`
	UploadSpeed   int64           `json:"uploadSpeed"`
	DownloadSpeed int64           `json:"downloadSpeed"`
	Connections   []ConnectionRow `json:"connections"`
	Closed        []ConnectionRow `json:"closed"`
}

const (
	subscriptionUserAgent = "clash-verge/v2.5.2"
	defaultDelayTestURL   = "https://www.gstatic.com/generate_204"
	coreServiceStartFlag  = "--start-core-service"
)

var (
	AppVersion  = "P0"
	BuildNumber = "0"
)

func NewApp() *App {
	return &App{
		httpClient:        &http.Client{Timeout: 12 * time.Second},
		connectionSamples: map[string]connectionSample{},
	}
}

func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
	if err := a.initStore(); err != nil {
		a.appendLog("error", err.Error())
		return
	}
	a.appendLog("info", "Pulse Wails client started")
	a.syncAutoStartPath()
	if err := registerURLProtocol(); err != nil {
		a.appendLog("error", "register clash URL protocol failed: "+err.Error())
	}
	startHidden, startCoreService := a.handleLaunchArgs(os.Args[1:])
	a.updateTrayMenuState()
	if startHidden {
		wailsruntime.WindowHide(ctx)
	}
	a.startShowSignalWatcher()
	go func() {
		if err := a.EnsureGeodata(); err != nil {
			a.appendLog("error", "geodata download failed: "+err.Error())
		}
	}()
	if startCoreService || a.store.Settings.AutoStartCore {
		go func() {
			time.Sleep(300 * time.Millisecond)
			if err := a.StartCore(); err != nil {
				a.appendLog("error", "auto start mihomo failed: "+err.Error())
			}
		}()
	}
}

func (a *App) syncAutoStartPath() {
	a.mu.Lock()
	enabled := a.store.Settings.AutoStart
	a.mu.Unlock()
	if enabled {
		if err := setAutoStart(true); err != nil {
			a.appendLog("error", "auto-start path sync failed: "+err.Error())
		} else {
			a.appendLog("info", "auto-start path synced to current executable")
		}
	}
}

func (a *App) Shutdown(ctx context.Context) {
	a.mu.Lock()
	settings := a.store.Settings
	a.mu.Unlock()
	if !coreRunsAsRegisteredWindowsService(settings) {
		_ = a.StopCore()
	}
	quitTray()
}

func (a *App) BeforeClose(ctx context.Context) bool {
	a.mu.Lock()
	forceQuit := a.forceQuit
	closeBehavior := a.store.Settings.CloseBehavior
	a.mu.Unlock()
	if forceQuit || closeBehavior == "exit" {
		return false
	}
	wailsruntime.WindowHide(ctx)
	return true
}

func (a *App) CloseWindow() {
	a.mu.Lock()
	closeBehavior := a.store.Settings.CloseBehavior
	a.mu.Unlock()
	if closeBehavior == "exit" {
		a.quitApplication()
		return
	}
	wailsruntime.WindowHide(a.ctx)
}

func (a *App) ExitKeepServiceRunning() {
	a.mu.Lock()
	a.forceQuit = true
	a.mu.Unlock()
	quitTray()
	wailsruntime.Quit(a.ctx)
}

func (a *App) MinimizeWindow() {
	wailsruntime.WindowHide(a.ctx)
}

func (a *App) IsAdministrator() bool {
	return isProcessElevated()
}

func (a *App) RelaunchAsAdministrator() error {
	if isProcessElevated() {
		return nil
	}
	if err := relaunchAsAdministrator(); err != nil {
		return err
	}
	return nil
}

func (a *App) ShowWindow() {
	if a.ctx == nil {
		return
	}
	wailsruntime.WindowUnminimise(a.ctx)
	wailsruntime.WindowShow(a.ctx)
}

func (a *App) handleLaunchArgs(args []string) (startHidden bool, startCoreService bool) {
	for _, arg := range args {
		if arg == "--start-hidden" || arg == "-start-hidden" {
			startHidden = true
			continue
		}
		if arg == coreServiceStartFlag {
			startCoreService = true
			continue
		}
		if strings.Contains(arg, "install-config") {
			if err := a.ProcessInstallConfigURL(arg); err != nil {
				a.appendLog("error", "install config import failed: "+err.Error())
			}
		}
	}
	return startHidden, startCoreService
}

func (a *App) ProcessInstallConfigURL(raw string) error {
	subscriptionURL, err := extractInstallConfigURL(raw)
	if err != nil {
		return err
	}
	_, err = a.AddProfileFromURL("", subscriptionURL)
	if err == nil {
		a.appendLog("info", "subscription imported from URL protocol")
	}
	return err
}

func (a *App) startShowSignalWatcher() {
	if a.showSignalPath == "" {
		return
	}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for range ticker.C {
			a.mu.Lock()
			forceQuit := a.forceQuit
			a.mu.Unlock()
			if forceQuit {
				return
			}
			info, err := os.Stat(a.showSignalPath)
			if err != nil {
				continue
			}
			if info.ModTime().After(a.lastShowSignalTime) {
				a.lastShowSignalTime = info.ModTime()
				if data, err := os.ReadFile(a.showSignalPath); err == nil {
					value := strings.TrimSpace(string(data))
					if strings.Contains(value, "install-config") {
						if err := a.ProcessInstallConfigURL(value); err != nil {
							a.appendLog("error", "install config import failed: "+err.Error())
						}
					}
				}
				a.ShowWindow()
			}
		}
	}()
}

func (a *App) quitApplication() {
	a.mu.Lock()
	a.forceQuit = true
	a.mu.Unlock()
	quitTray()
	wailsruntime.Quit(a.ctx)
}

func (a *App) initStore() error {
	configDir, err := os.UserConfigDir()
	if err != nil {
		configDir = "."
	}
	a.dataDir = filepath.Join(configDir, "Pulse")
	a.storePath = filepath.Join(a.dataDir, "store.json")
	a.showSignalPath = filepath.Join(a.dataDir, "show.signal")
	if err := os.MkdirAll(filepath.Join(a.dataDir, "profiles"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(a.dataDir, "backgrounds"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(a.dataDir, "logs"), 0o755); err != nil {
		return err
	}

	if _, err := os.Stat(a.storePath); errors.Is(err, os.ErrNotExist) {
		profilePath := filepath.Join(a.dataDir, "profiles", "direct.yaml")
		if err := os.WriteFile(profilePath, []byte(defaultProfileYAML), 0o644); err != nil {
			return err
		}
		a.store = Store{
			ActiveProfileID: "direct",
			Profiles: []Profile{{
				ID:        "direct",
				Name:      "Direct",
				Type:      "local",
				Path:      profilePath,
				UpdatedAt: time.Now().Unix(),
				Enabled:   true,
			}},
			Settings: defaultSettings(),
		}
		return a.saveStoreLocked()
	}

	data, err := os.ReadFile(a.storePath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &a.store); err != nil {
		return err
	}
	needsSave := strings.TrimSpace(a.store.Settings.Secret) == ""
	missingAutoStartCore := !storeHasSetting(data, "autoStartCore")
	missingBackgroundOpacity := !storeHasSetting(data, "backgroundOpacity")
	missingTunDefaults := !storeHasSetting(data, "tunStack")
	a.store.Settings = mergeSettings(a.store.Settings, defaultSettings())
	if missingAutoStartCore {
		a.store.Settings.AutoStartCore = true
	}
	if missingBackgroundOpacity {
		a.store.Settings.BackgroundOpacity = defaultSettings().BackgroundOpacity
	}
	if missingTunDefaults {
		defaults := defaultSettings()
		a.store.Settings.TunStack = defaults.TunStack
		a.store.Settings.TunAutoRoute = defaults.TunAutoRoute
		a.store.Settings.TunAutoRedirect = defaults.TunAutoRedirect
		a.store.Settings.TunAutoDetect = defaults.TunAutoDetect
		a.store.Settings.TunDNSHijack = defaults.TunDNSHijack
	}
	if needsSave || missingAutoStartCore || missingBackgroundOpacity || missingTunDefaults {
		return a.saveStoreLocked()
	}
	return nil
}

func defaultSettings() Settings {
	core := "mihomo"
	if goruntime.GOOS == "windows" {
		core = "mihomo.exe"
	}
	return Settings{
		CorePath:          core,
		CoreMode:          "embedded",
		ApiBase:           "http://127.0.0.1:9090",
		Secret:            randomSecret(),
		MixedPort:         7890,
		Mode:              "rule",
		LogLevel:          "info",
		Language:          "zh",
		Theme:             "system",
		TunEnabled:        false,
		TunStack:          "mixed",
		TunAutoRoute:      true,
		TunAutoRedirect:   true,
		TunAutoDetect:     true,
		TunDNSHijack:      []string{"any:53", "tcp://any:53"},
		DelayTestURL:      defaultDelayTestURL,
		AutoStartCore:     true,
		CloseBehavior:     "minimize",
		SubscriptionProxy: false,
		BackgroundOpacity: 62,
	}
}

func mergeSettings(current, defaults Settings) Settings {
	if current.CorePath == "" {
		current.CorePath = defaults.CorePath
	}
	if current.CoreMode == "" {
		current.CoreMode = defaults.CoreMode
	}
	if current.CoreMode == "service" && goruntime.GOOS != "windows" {
		current.CoreMode = defaults.CoreMode
	}
	if current.ApiBase == "" {
		current.ApiBase = defaults.ApiBase
	}
	if strings.TrimSpace(current.Secret) == "" {
		current.Secret = defaults.Secret
	}
	if current.MixedPort == 0 {
		current.MixedPort = defaults.MixedPort
	}
	if current.Mode == "" {
		current.Mode = defaults.Mode
	}
	if current.LogLevel == "" {
		current.LogLevel = defaults.LogLevel
	}
	if current.Language == "" {
		current.Language = defaults.Language
	}
	if strings.TrimSpace(current.DelayTestURL) == "" {
		current.DelayTestURL = defaults.DelayTestURL
	}
	if current.Theme == "" {
		current.Theme = defaults.Theme
	}
	if current.TunStack == "" {
		current.TunStack = defaults.TunStack
	}
	if len(current.TunDNSHijack) == 0 {
		current.TunDNSHijack = defaults.TunDNSHijack
	}
	if len(current.TunIncludeIF) > 0 && len(current.TunExcludeIF) > 0 {
		current.TunExcludeIF = nil
	}
	if current.CloseBehavior == "" {
		current.CloseBehavior = defaults.CloseBehavior
	}
	if current.AutoStart {
		current.AutoStartService = false
	} else if current.AutoStartService {
		current.AutoStart = false
	}
	if !current.AutoStartService {
		current.AutoStartServiceDaemon = false
	}
	if current.CoreMode == "service" {
		// Legacy "service" CoreMode is now expressed as "embedded" with the
		// AutoStartService toggle flipped on.
		current.CoreMode = "embedded"
		current.AutoStartService = true
	}
	if appHasEmbeddedCore() && current.AutoStartService {
		// App-embedded builds do not ship PulseStartupService.exe, so the
		// boot autostart service has no helper to register. Auto-disable
		// the toggle so legacy configs do not try to install a service
		// that the binary cannot run.
		current.AutoStartService = false
		current.AutoStartServiceDaemon = false
	}
	current.BackgroundBlur = clampBackgroundBlur(current.BackgroundBlur)
	current.BackgroundOpacity = clampBackgroundOpacity(current.BackgroundOpacity)
	return current
}

func storeHasSetting(data []byte, key string) bool {
	var raw struct {
		Settings map[string]json.RawMessage `json:"settings"`
	}
	if err := json.Unmarshal(data, &raw); err != nil || raw.Settings == nil {
		return false
	}
	_, ok := raw.Settings[key]
	return ok
}

func randomSecret() string {
	token := make([]byte, 24)
	if _, err := rand.Read(token); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(token)
}

func extractInstallConfigURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("install config URL is empty")
	}
	value := ""
	if parsed, err := url.Parse(raw); err == nil {
		value = parsed.Query().Get("url")
	}
	if value == "" {
		matches := regexp.MustCompile(`(?i)(?:^|[?&])url=([^&]+)`).FindStringSubmatch(raw)
		if len(matches) > 1 {
			value = matches[1]
		}
	}
	if value == "" {
		return "", errors.New("install config URL has no url parameter")
	}
	for i := 0; i < 2; i++ {
		decoded, err := url.QueryUnescape(value)
		if err != nil || decoded == value {
			break
		}
		value = decoded
	}
	if parsed, err := url.Parse(value); err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("install config URL parameter is not a valid remote URL")
	}
	return value, nil
}

func clampBackgroundBlur(value int) int {
	if value < 0 {
		return 0
	}
	if value > 40 {
		return 40
	}
	return value
}

func clampBackgroundOpacity(value int) int {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func normalizeLogLevel(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug", "info", "warning", "warn", "error", "silent":
		if strings.ToLower(strings.TrimSpace(value)) == "warn" {
			return "warning"
		}
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "info"
	}
}

func (a *App) GetSnapshot() RuntimeState {
	a.mu.Lock()
	settings := a.store.Settings
	profiles := append([]Profile(nil), a.store.Profiles...)
	active := a.activeProfileNameLocked()
	running := a.coreRunningLocked()
	startedAt := a.startedAt
	logs := a.recentLogsLocked(80)
	dataDir := a.dataDir
	geodata := a.geodataStatus
	a.mu.Unlock()

	traffic, apiOK := a.fetchTraffic()
	return RuntimeState{
		Running:                running,
		ApiReachable:           apiOK,
		CoreFound:              a.coreAvailable(settings),
		Version:                AppVersion,
		BuildNumber:            BuildNumber,
		Platform:               goruntime.GOOS,
		AppEmbeddedCore:        appHasEmbeddedCore(),
		ServiceEmbeddedCore:    serviceHelperHasEmbeddedCore(),
		CoreModeImplementation: coreModeImplementation(settings),
		StartedAt:              startedAt,
		DataDir:                dataDir,
		ActiveProfile:          active,
		Profiles:               profiles,
		Settings:               settings,
		Traffic:                traffic,
		RecentLogs:             logs,
		Geodata:                geodata,
	}
}

func (a *App) SaveSettings(settings Settings) error {
	settings = mergeSettings(settings, defaultSettings())
	settings.LogLevel = normalizeLogLevel(settings.LogLevel)
	if settings.AutoStart {
		settings.AutoStartService = false
	} else if settings.AutoStartService {
		settings.AutoStart = false
	}
	if !settings.AutoStartService {
		settings.AutoStartServiceDaemon = false
	}
	a.appendLog("info", fmt.Sprintf(
		"save settings requested: store=%s coreMode=%s autoStartCore=%t autoStart=%t serviceStartup=%t systemProxy=%t allowLan=%t mixedPort=%d tun=%t interface=%s",
		a.storePath,
		settings.CoreMode,
		settings.AutoStartCore,
		settings.AutoStart,
		settings.AutoStartService,
		settings.SystemProxy,
		settings.AllowLan,
		settings.MixedPort,
		settings.TunEnabled,
		strings.TrimSpace(settings.TunInterface),
	))
	a.mu.Lock()
	previous := a.store.Settings
	running := a.coreRunningLocked()
	if settingsNeedTunAdmin(previous, settings, running) && !isProcessElevated() && !coreRunsAsRegisteredWindowsService(settings) {
		a.mu.Unlock()
		a.appendLog("error", tunAdminRequiredMessage)
		return errors.New(tunAdminRequiredMessage)
	}
	requiresRestart := running && settingsRequireCoreRestart(previous, settings)
	requiresConfigReload := running && settingsRequireConfigReload(previous, settings)
	requiresRuntimeApply := running && settingsRequireRuntimeApply(previous, settings)
	requiresSystemProxyApply := running || previous.SystemProxy != settings.SystemProxy || (settings.SystemProxy && previous.MixedPort != settings.MixedPort)
	requiresAutoStartApply := previous.AutoStart != settings.AutoStart || (settings.AutoStart && isProcessElevated())
	requiresServiceStartupApply := previous.AutoStartService != settings.AutoStartService
	requiresServiceStartupSync := settings.AutoStartService && previous.AutoStartServiceDaemon != settings.AutoStartServiceDaemon
	dataDir := a.dataDir
	a.mu.Unlock()

	if requiresAutoStartApply {
		if err := setAutoStart(settings.AutoStart); err != nil {
			a.appendLog("error", "save settings auto-start apply failed: "+err.Error())
			return err
		}
		a.appendLog("info", fmt.Sprintf("save settings auto-start applied: enabled=%t", settings.AutoStart))
	}
	if requiresServiceStartupApply {
		if settings.AutoStartService && !isProcessElevated() {
			// Registering the service needs admin. Trigger the UAC
			// relaunch; the elevated process will see
			// AutoStartService=true from the saved store.json on its
			// next Startup and run setServiceAutoStart itself. The
			// relaunch script kills the current non-elevated process
			// so the elevated instance is the only one left.
			if relaunchErr := relaunchAsAdministratorWithArgs(nil); relaunchErr == nil {
				a.appendLog("info", "save settings service startup requires admin, requesting UAC")
				return nil
			} else {
				a.appendLog("error", "save settings service startup UAC request failed: "+relaunchErr.Error())
				return errors.New("注册服务需要管理员权限，请允许 UAC 提示")
			}
		}
		if err := setServiceAutoStart(dataDir, settings, settings.AutoStartService); err != nil {
			a.appendLog("error", "save settings service startup apply failed: "+err.Error())
			return err
		}
		a.appendLog("info", fmt.Sprintf("save settings service startup applied: enabled=%t", settings.AutoStartService))
	} else if requiresServiceStartupSync {
		if err := syncStartupServicePayload(dataDir, settings); err != nil {
			a.appendLog("warn", "save settings service startup sync failed: "+err.Error())
		}
	}

	a.mu.Lock()
	a.store.Settings = settings
	err := a.saveStoreLocked()
	a.mu.Unlock()
	if err != nil {
		a.appendLog("error", "save settings store write failed: "+err.Error())
		return err
	}
	a.appendLog("info", "save settings store write complete")
	if requiresRestart {
		a.appendLog("info", "settings require mihomo restart, restarting core")
		if previous.SystemProxy {
			if err := configureSystemProxy(previous, false); err != nil {
				a.appendLog("warn", "disable previous system proxy before restart failed: "+err.Error())
			}
		}
		if err := a.RestartCore(); err != nil {
			a.appendLog("error", "restart core after settings change failed: "+err.Error())
			return err
		}
		return nil
	}
	if requiresConfigReload {
		a.appendLog("info", "settings require mihomo config reload")
		if err := a.reloadActiveRuntimeConfig(); err != nil {
			a.appendLog("error", "reload config after settings change failed: "+err.Error())
			return err
		}
	}
	if requiresRuntimeApply {
		if err := a.applyRuntimeSettings(settings); err != nil {
			a.appendLog("warn", "apply runtime settings failed: "+err.Error())
			return err
		}
	}
	if requiresSystemProxyApply {
		if err := configureSystemProxy(settings, settings.SystemProxy); err != nil {
			a.appendLog("error", "system proxy apply failed: "+err.Error())
			return err
		}
		a.appendLog("info", "system proxy setting applied: "+systemProxyState())
	}
	return nil
}

func (a *App) SetMode(mode string) error {
	a.mu.Lock()
	settings := a.store.Settings
	a.mu.Unlock()
	settings.Mode = mode
	return a.SaveSettings(settings)
}

func (a *App) SetAllowLan(enabled bool) error {
	a.mu.Lock()
	settings := a.store.Settings
	a.mu.Unlock()
	settings.AllowLan = enabled
	return a.SaveSettings(settings)
}

func (a *App) SetSystemProxy(enabled bool) error {
	a.mu.Lock()
	settings := a.store.Settings
	a.mu.Unlock()
	settings.SystemProxy = enabled
	return a.SaveSettings(settings)
}

func (a *App) SetSubscriptionProxy(enabled bool) error {
	a.mu.Lock()
	settings := a.store.Settings
	a.mu.Unlock()
	settings.SubscriptionProxy = enabled
	return a.SaveSettings(settings)
}

func (a *App) SetAutoStart(enabled bool) error {
	a.mu.Lock()
	settings := a.store.Settings
	a.mu.Unlock()
	settings.AutoStart = enabled
	return a.SaveSettings(settings)
}

func (a *App) SetAutoStartService(enabled bool) error {
	a.mu.Lock()
	settings := a.store.Settings
	a.mu.Unlock()
	settings.AutoStartService = enabled
	return a.SaveSettings(settings)
}

func (a *App) ListNetworkInterfaces() ([]NetworkInterface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	rows := make([]NetworkInterface, 0, len(interfaces))
	for _, item := range interfaces {
		if item.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses := []string{}
		if addrs, err := item.Addrs(); err == nil {
			for _, addr := range addrs {
				addresses = append(addresses, addr.String())
			}
		}
		rows = append(rows, NetworkInterface{
			Name:        item.Name,
			DisplayName: item.Name,
			Addresses:   addresses,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows, nil
}

func settingsRequireCoreRestart(previous, next Settings) bool {
	return previous.CoreMode != next.CoreMode ||
		previous.CorePath != next.CorePath ||
		previous.ApiBase != next.ApiBase ||
		previous.Secret != next.Secret
}

func settingsRequireConfigReload(previous, next Settings) bool {
	return previous.MixedPort != next.MixedPort ||
		tunSettingsChanged(previous, next)
}

func settingsNeedTunAdmin(previous, next Settings, running bool) bool {
	if !next.TunEnabled {
		return false
	}
	return running || !previous.TunEnabled || tunSettingsChanged(previous, next)
}

func tunSettingsChanged(previous, next Settings) bool {
	return !reflect.DeepEqual(tunSettingsSnapshot(previous), tunSettingsSnapshot(next))
}

func tunSettingsSnapshot(settings Settings) any {
	return struct {
		Enabled           bool
		Interface         string
		Stack             string
		AutoRoute         bool
		AutoRedirect      bool
		AutoDetect        bool
		DNSHijack         []string
		Device            string
		MTU               int
		StrictRoute       bool
		GSO               bool
		GSOMaxSize        int
		Inet6Address      string
		UDPTimeout        int
		IPRoute2Table     int
		IPRoute2Rule      int
		EINAT             bool
		RouteSet          []string
		RouteExcludeSet   []string
		RouteAddress      []string
		RouteExclude      []string
		IncludeIF         []string
		ExcludeIF         []string
		IncludeUID        []int
		IncludeUIDRange   []string
		ExcludeUID        []int
		ExcludeUIDRange   []string
		IncludeAndroid    []int
		IncludePackage    []string
		ExcludePackage    []string
		Inet4Route        []string
		Inet6Route        []string
		Inet4RouteExclude []string
		Inet6RouteExclude []string
	}{
		Enabled:           settings.TunEnabled,
		Interface:         strings.TrimSpace(settings.TunInterface),
		Stack:             strings.TrimSpace(settings.TunStack),
		AutoRoute:         settings.TunAutoRoute,
		AutoRedirect:      settings.TunAutoRedirect,
		AutoDetect:        settings.TunAutoDetect,
		DNSHijack:         settings.TunDNSHijack,
		Device:            strings.TrimSpace(settings.TunDevice),
		MTU:               settings.TunMTU,
		StrictRoute:       settings.TunStrictRoute,
		GSO:               settings.TunGSO,
		GSOMaxSize:        settings.TunGSOMaxSize,
		Inet6Address:      strings.TrimSpace(settings.TunInet6Address),
		UDPTimeout:        settings.TunUDPTimeout,
		IPRoute2Table:     settings.TunIPRoute2Table,
		IPRoute2Rule:      settings.TunIPRoute2Rule,
		EINAT:             settings.TunEINAT,
		RouteSet:          settings.TunRouteSet,
		RouteExcludeSet:   settings.TunRouteExcludeSet,
		RouteAddress:      settings.TunRouteAddress,
		RouteExclude:      settings.TunRouteExclude,
		IncludeIF:         settings.TunIncludeIF,
		ExcludeIF:         settings.TunExcludeIF,
		IncludeUID:        settings.TunIncludeUID,
		IncludeUIDRange:   settings.TunIncludeUIDRange,
		ExcludeUID:        settings.TunExcludeUID,
		ExcludeUIDRange:   settings.TunExcludeUIDRange,
		IncludeAndroid:    settings.TunIncludeAndroid,
		IncludePackage:    settings.TunIncludePackage,
		ExcludePackage:    settings.TunExcludePackage,
		Inet4Route:        settings.TunInet4Route,
		Inet6Route:        settings.TunInet6Route,
		Inet4RouteExclude: settings.TunInet4RouteExclude,
		Inet6RouteExclude: settings.TunInet6RouteExclude,
	}
}

func settingsRequireRuntimeApply(previous, next Settings) bool {
	return previous.AllowLan != next.AllowLan ||
		previous.Mode != next.Mode ||
		previous.LogLevel != next.LogLevel
}

func (a *App) AddProfileFromURL(name string, source string) (Profile, error) {
	name = strings.TrimSpace(name)
	source = strings.TrimSpace(source)
	if source == "" {
		return Profile{}, errors.New("subscription URL is empty")
	}
	body, headers, err := a.downloadProfile(source)
	if err != nil {
		return Profile{}, err
	}
	name = inferProfileName(name, source, headers, body)
	profile, err := a.writeProfile(name, "subscription", source, body, parseSubscriptionInfo(headers))
	if err == nil {
		a.appendLog("info", "subscription updated: "+name)
	}
	return profile, err
}

func (a *App) ImportProfile(name string, content string) (Profile, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Local Profile"
	}
	if strings.TrimSpace(content) == "" {
		return Profile{}, errors.New("profile content is empty")
	}
	return a.writeProfile(name, "local", "", []byte(content), SubscriptionInfo{})
}

func (a *App) ImportProfileFromFile(path string) (Profile, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Profile{}, errors.New("profile file path is empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, err
	}
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if name == "" {
		name = "Local Profile"
	}
	return a.writeProfile(name, "local", "", data, SubscriptionInfo{})
}

func (a *App) UpdateProfile(profileID string) (Profile, error) {
	a.mu.Lock()
	profile, ok := a.profileByIDLocked(profileID)
	a.mu.Unlock()
	if !ok {
		return Profile{}, errors.New("profile not found")
	}
	if profile.Source == "" {
		return profile, errors.New("local profile has no subscription URL")
	}
	body, headers, err := a.downloadProfile(profile.Source)
	if err != nil {
		return Profile{}, err
	}
	if err := os.WriteFile(profile.Path, body, 0o644); err != nil {
		return Profile{}, err
	}
	if isGeneratedProfileName(profile.Name, profile.ID) {
		profile.Name = inferProfileName("", profile.Source, headers, body)
	}
	if info := parseSubscriptionInfo(headers); subscriptionInfoHasData(info) {
		profile.Subscription = info
	}
	profile.UpdatedAt = time.Now().Unix()
	a.mu.Lock()
	for i := range a.store.Profiles {
		if a.store.Profiles[i].ID == profile.ID {
			a.store.Profiles[i] = profile
			break
		}
	}
	err = a.saveStoreLocked()
	a.mu.Unlock()
	if err == nil {
		a.appendLog("info", "subscription updated: "+profile.Name)
	}
	return profile, err
}

func (a *App) RenameProfile(profileID string, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("profile name is empty")
	}
	a.mu.Lock()
	for i := range a.store.Profiles {
		if a.store.Profiles[i].ID == profileID {
			a.store.Profiles[i].Name = name
			a.store.Profiles[i].UpdatedAt = time.Now().Unix()
			err := a.saveStoreLocked()
			a.mu.Unlock()
			a.updateTrayMenuState()
			return err
		}
	}
	a.mu.Unlock()
	return errors.New("profile not found")
}

func (a *App) SetActiveProfile(profileID string) error {
	a.mu.Lock()
	if _, ok := a.profileByIDLocked(profileID); !ok {
		a.mu.Unlock()
		return errors.New("profile not found")
	}
	running := a.coreRunningLocked()
	a.store.ActiveProfileID = profileID
	err := a.saveStoreLocked()
	a.mu.Unlock()
	if err != nil {
		return err
	}
	a.updateTrayMenuState()
	if running {
		if err := a.reloadActiveRuntimeConfig(); err != nil {
			a.appendLog("warn", "reload profile config failed, restarting core: "+err.Error())
			return a.RestartCore()
		}
		a.appendLog("info", "profile config reloaded without core restart")
	}
	return nil
}

func (a *App) DeleteProfile(profileID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	next := a.store.Profiles[:0]
	var removed *Profile
	for _, profile := range a.store.Profiles {
		if profile.ID == profileID {
			copy := profile
			removed = &copy
			continue
		}
		next = append(next, profile)
	}
	if removed == nil {
		return errors.New("profile not found")
	}
	if len(next) == 0 {
		return errors.New("at least one profile is required")
	}
	a.store.Profiles = next
	if a.store.ActiveProfileID == profileID {
		a.store.ActiveProfileID = next[0].ID
	}
	_ = os.Remove(removed.Path)
	return a.saveStoreLocked()
}

func (a *App) ReadProfileContent(profileID string) (string, error) {
	a.mu.Lock()
	profile, ok := a.profileByIDLocked(profileID)
	a.mu.Unlock()
	if !ok {
		return "", errors.New("profile not found")
	}
	data, err := os.ReadFile(profile.Path)
	return string(data), err
}

func (a *App) SaveProfileContent(profileID string, content string) error {
	a.mu.Lock()
	profile, ok := a.profileByIDLocked(profileID)
	a.mu.Unlock()
	if !ok {
		return errors.New("profile not found")
	}
	if strings.TrimSpace(content) == "" {
		return errors.New("profile content is empty")
	}
	if err := os.WriteFile(profile.Path, []byte(content), 0o644); err != nil {
		return err
	}
	a.mu.Lock()
	for i := range a.store.Profiles {
		if a.store.Profiles[i].ID == profileID {
			a.store.Profiles[i].UpdatedAt = time.Now().Unix()
			break
		}
	}
	err := a.saveStoreLocked()
	a.mu.Unlock()
	return err
}

func (a *App) ReadProfileCustomRules(profileID string) ([]CustomRule, error) {
	a.mu.Lock()
	profile, ok := a.profileByIDLocked(profileID)
	a.mu.Unlock()
	if !ok {
		return nil, errors.New("profile not found")
	}
	rules, err := a.readProfileCustomRules(profile)
	if err != nil {
		return nil, err
	}
	return rules, nil
}

func (a *App) ReadProfileRulePolicies(profileID string) ([]string, error) {
	a.mu.Lock()
	profile, ok := a.profileByIDLocked(profileID)
	a.mu.Unlock()
	if !ok {
		return nil, errors.New("profile not found")
	}
	return profileRulePolicies(profile.Path)
}

func (a *App) SaveProfileCustomRules(profileID string, rules []CustomRule) error {
	a.mu.Lock()
	profile, ok := a.profileByIDLocked(profileID)
	if !ok {
		a.mu.Unlock()
		return errors.New("profile not found")
	}
	running := a.coreRunningLocked()
	activeProfileID := a.store.ActiveProfileID
	a.mu.Unlock()
	if err := a.writeProfileCustomRules(profile.ID, normalizeCustomRuleRows(rules)); err != nil {
		return err
	}
	if running && activeProfileID == profileID {
		if err := a.reloadActiveRuntimeConfig(); err != nil {
			a.appendLog("warn", "reload custom rules failed, restarting core: "+err.Error())
			return a.RestartCore()
		}
	}
	return nil
}

func (a *App) customRulesPath(profileID string) string {
	return filepath.Join(a.dataDir, "custom-rules", sanitizeFilename(profileID)+".json")
}

func (a *App) readProfileCustomRules(profile Profile) ([]CustomRule, error) {
	data, err := os.ReadFile(a.customRulesPath(profile.ID))
	if err == nil {
		var rules []CustomRule
		if err := json.Unmarshal(data, &rules); err != nil {
			return nil, err
		}
		return normalizeCustomRuleRows(rules), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return []CustomRule{}, nil
}

func (a *App) writeProfileCustomRules(profileID string, rules []CustomRule) error {
	dir := filepath.Dir(a.customRulesPath(profileID))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(a.customRulesPath(profileID), data, 0o644)
}

func profileRulePolicies(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse profile YAML: %w", err)
	}
	root := yamlRootMapping(&doc)
	if root == nil {
		return nil, errors.New("profile YAML root must be a mapping")
	}
	groups := yamlMappingValue(root, "proxy-groups")
	if groups == nil || groups.Kind != yaml.SequenceNode {
		return []string{"DIRECT", "REJECT"}, nil
	}
	seen := map[string]bool{}
	policies := make([]string, 0, len(groups.Content)+2)
	for _, item := range groups.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		name := strings.TrimSpace(yamlScalarString(yamlMappingValue(item, "name")))
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		policies = append(policies, name)
	}
	for _, name := range []string{"DIRECT", "REJECT"} {
		if !seen[name] {
			policies = append(policies, name)
		}
	}
	return policies, nil
}

func (a *App) StartCore() error {
	a.mu.Lock()
	if a.coreRunningLocked() {
		a.mu.Unlock()
		return nil
	}
	settings := a.store.Settings
	profile, ok := a.activeProfileLocked()
	a.mu.Unlock()
	if !ok {
		return errors.New("no active profile")
	}
	useService := coreRunsAsRegisteredWindowsService(settings)
	if settings.TunEnabled && !isProcessElevated() && !useService {
		a.appendLog("error", tunAdminRequiredMessage)
		return errors.New(tunAdminRequiredMessage)
	}
	if err := a.EnsureGeodata(); err != nil {
		return err
	}
	runtimeConfig, err := a.buildRuntimeConfig(profile, settings)
	if err != nil {
		return err
	}
	switch {
	case useService:
		if err := startServiceCore(a.dataDir, settings, runtimeConfig); err != nil {
			return err
		}
		a.mu.Lock()
		a.serviceCoreRunning = true
		a.startedAt = time.Now().Unix()
		a.mu.Unlock()
	case settings.CoreMode == "custom":
		corePath, err := a.resolveCorePath(settings.CorePath)
		if err != nil {
			return err
		}
		cmd := exec.Command(corePath, "-d", a.dataDir, "-f", runtimeConfig)
		setCoreProcessOptions(cmd)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return err
		}
		stderr, err := cmd.StderrPipe()
		if err != nil {
			return err
		}
		if err := cmd.Start(); err != nil {
			return err
		}

		a.mu.Lock()
		a.coreCmd = cmd
		a.startedAt = time.Now().Unix()
		a.mu.Unlock()

		go a.scanCoreOutput(stdout, "info")
		go a.scanCoreOutput(stderr, "warn")
		go func() {
			err := cmd.Wait()
			a.mu.Lock()
			if a.coreCmd == cmd {
				a.coreCmd = nil
				a.startedAt = 0
			}
			a.mu.Unlock()
			if err != nil {
				a.appendLog("error", "mihomo stopped: "+err.Error())
				return
			}
			a.appendLog("info", "mihomo stopped")
		}()
	default:
		if err := a.startEmbeddedCore(runtimeConfig, settings); err != nil {
			return err
		}
	}
	if err := a.waitForAPIReady(8 * time.Second); err != nil {
		if useService {
			a.mu.Lock()
			a.serviceCoreRunning = false
			a.startedAt = 0
			a.mu.Unlock()
		} else if settings.CoreMode != "custom" {
			a.stopEmbeddedCore()
			a.mu.Lock()
			cmd := a.coreCmd
			a.coreCmd = nil
			a.embeddedCoreRunning = false
			a.serviceCoreRunning = false
			a.startedAt = 0
			a.mu.Unlock()
			if cmd != nil && cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		}
		return err
	}
	if settings.SystemProxy {
		a.appendLog("info", "enabling system proxy before state: "+systemProxyState())
		if err := configureSystemProxy(settings, true); err != nil {
			a.appendLog("error", "enable system proxy failed: "+err.Error())
			return err
		}
		a.appendLog("info", "enabling system proxy after state: "+systemProxyState())
	}
	a.appendLog("info", "mihomo started with profile: "+profile.Name)
	a.updateTrayMenuState()
	return nil
}

func (a *App) StopCore() error {
	a.mu.Lock()
	cmd := a.coreCmd
	embedded := a.embeddedCoreRunning
	serviceCore := a.serviceCoreRunning
	settings := a.store.Settings
	a.coreCmd = nil
	a.embeddedCoreRunning = false
	a.serviceCoreRunning = false
	a.startedAt = 0
	a.mu.Unlock()
	if settings.SystemProxy {
		a.appendLog("info", "disabling system proxy before state: "+systemProxyState())
		if err := configureSystemProxy(settings, false); err != nil {
			a.appendLog("warn", "disable system proxy failed: "+err.Error())
		} else {
			a.appendLog("info", "disabling system proxy after state: "+systemProxyState())
		}
	}
	if cmd == nil || cmd.Process == nil {
		if serviceCore {
			if err := stopServiceCore(a.dataDir); err != nil {
				return err
			}
			a.appendLog("info", "service core stop requested")
		}
		if embedded {
			a.stopEmbeddedCore()
			a.appendLog("info", "mihomo stop requested")
		}
		a.updateTrayMenuState()
		return nil
	}
	if embedded {
		a.stopEmbeddedCore()
		time.Sleep(150 * time.Millisecond)
	}
	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	a.appendLog("info", "mihomo stop requested")
	a.updateTrayMenuState()
	return nil
}

func (a *App) RestartCore() error {
	if err := a.StopCore(); err != nil {
		return err
	}
	time.Sleep(400 * time.Millisecond)
	return a.StartCore()
}

func (a *App) reloadActiveRuntimeConfig() error {
	a.mu.Lock()
	settings := a.store.Settings
	profile, ok := a.activeProfileLocked()
	running := a.coreRunningLocked()
	a.mu.Unlock()
	if !running {
		return nil
	}
	if !ok {
		return errors.New("no active profile")
	}
	runtimeConfig, err := a.buildRuntimeConfig(profile, settings)
	if err != nil {
		return err
	}
	if handled, err := a.reloadManagedRuntimeConfig(runtimeConfig, settings); handled {
		if err != nil {
			return err
		}
		a.updateTrayMenuState()
		return nil
	}
	body := map[string]any{"path": runtimeConfig}
	if err := a.apiRequest(http.MethodPut, "/configs?force=true", body, nil); err != nil {
		return err
	}
	a.updateTrayMenuState()
	return nil
}

func (a *App) FetchProxyGroups() ([]ProxyGroup, error) {
	var raw struct {
		Proxies map[string]struct {
			Name    string   `json:"name"`
			Type    string   `json:"type"`
			Now     string   `json:"now"`
			All     []string `json:"all"`
			History []struct {
				Delay int `json:"delay"`
			} `json:"history"`
		} `json:"proxies"`
	}
	if err := a.apiRequest(http.MethodGet, "/proxies", nil, &raw); err != nil {
		return nil, err
	}
	groups := make([]ProxyGroup, 0)
	for name, proxy := range raw.Proxies {
		if len(proxy.All) == 0 {
			continue
		}
		group := ProxyGroup{Name: name, Type: proxy.Type, Now: proxy.Now}
		for _, nodeName := range proxy.All {
			nodeRaw := raw.Proxies[nodeName]
			delay := -1
			if len(nodeRaw.History) > 0 {
				delay = nodeRaw.History[len(nodeRaw.History)-1].Delay
			}
			group.Nodes = append(group.Nodes, ProxyNode{
				Name:  nodeName,
				Type:  nodeRaw.Type,
				Delay: delay,
				Alive: delay >= 0,
			})
		}
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	return groups, nil
}

func (a *App) SelectProxy(group string, name string) error {
	body := map[string]string{"name": name}
	if err := a.apiRequest(http.MethodPut, "/proxies/"+url.PathEscape(group), body, nil); err != nil {
		return err
	}
	a.updateTrayMenuState()
	return nil
}

func (a *App) TestProxyGroup(group string) error {
	groups, err := a.FetchProxyGroups()
	if err != nil {
		return err
	}
	testURL := a.delayTestURL()
	var target *ProxyGroup
	for i := range groups {
		if groups[i].Name == group {
			target = &groups[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("proxy group %q not found", group)
	}
	var wg sync.WaitGroup
	limit := make(chan struct{}, 8)
	for _, node := range target.Nodes {
		nodeName := node.Name
		wg.Add(1)
		go func() {
			defer wg.Done()
			limit <- struct{}{}
			defer func() { <-limit }()
			path := "/proxies/" + url.PathEscape(nodeName) + "/delay?timeout=5000&url=" + url.QueryEscape(testURL)
			if err := a.apiRequest(http.MethodGet, path, nil, nil); err != nil {
				a.appendLog("warning", fmt.Sprintf("proxy delay test failed: group=%s node=%s error=%s", group, nodeName, err.Error()))
			}
		}()
	}
	wg.Wait()
	a.updateTrayMenuState()
	return nil
}

func (a *App) TestProxyNode(group string, node string) error {
	if strings.TrimSpace(node) == "" {
		return errors.New("proxy node is empty")
	}
	path := "/proxies/" + url.PathEscape(node) + "/delay?timeout=5000&url=" + url.QueryEscape(a.delayTestURL())
	if err := a.apiRequest(http.MethodGet, path, nil, nil); err != nil {
		a.appendLog("warning", fmt.Sprintf("proxy delay test failed: group=%s node=%s error=%s", group, node, err.Error()))
		return err
	}
	a.updateTrayMenuState()
	return nil
}

func (a *App) delayTestURL() string {
	a.mu.Lock()
	value := strings.TrimSpace(a.store.Settings.DelayTestURL)
	a.mu.Unlock()
	if value == "" {
		return defaultDelayTestURL
	}
	return value
}

func (a *App) FetchRules() ([]RuleRow, error) {
	var raw struct {
		Rules []RuleRow `json:"rules"`
	}
	if err := a.apiRequest(http.MethodGet, "/rules", nil, &raw); err != nil {
		return nil, err
	}
	return raw.Rules, nil
}

func (a *App) FetchProviders() ([]ProviderRow, error) {
	a.mu.Lock()
	running := a.coreRunningLocked()
	a.mu.Unlock()
	if !running {
		return []ProviderRow{}, nil
	}
	var raw struct {
		Providers map[string]struct {
			Name      string `json:"name"`
			Vehicle   string `json:"vehicleType"`
			UpdatedAt string `json:"updatedAt"`
			Proxies   []any  `json:"proxies"`
		} `json:"providers"`
	}
	if err := a.apiRequest(http.MethodGet, "/providers/proxies", nil, &raw); err != nil {
		if isAPIUnavailableError(err) {
			a.appendLog("debug", "skip proxy providers refresh while mihomo API is unavailable: "+err.Error())
			return []ProviderRow{}, nil
		}
		return nil, err
	}
	rows := make([]ProviderRow, 0, len(raw.Providers))
	for name, provider := range raw.Providers {
		rowName := provider.Name
		if rowName == "" {
			rowName = name
		}
		rows = append(rows, ProviderRow{
			Name:      rowName,
			Vehicle:   provider.Vehicle,
			UpdatedAt: provider.UpdatedAt,
			Proxies:   len(provider.Proxies),
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows, nil
}

func isAPIUnavailableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "connection refused") ||
		strings.Contains(message, "actively refused") ||
		strings.Contains(message, "connectex") ||
		strings.Contains(message, "no connection could be made") ||
		strings.Contains(message, "connection reset by peer")
}

func (a *App) UpdateProvider(name string) error {
	return a.apiRequest(http.MethodPut, "/providers/proxies/"+url.PathEscape(name), nil, nil)
}

func (a *App) FetchConnections() (ConnectionSnapshot, error) {
	var raw struct {
		DownloadTotal int64  `json:"downloadTotal"`
		UploadTotal   int64  `json:"uploadTotal"`
		Memory        uint64 `json:"memory"`
		Connections   []struct {
			ID       string   `json:"id"`
			Network  string   `json:"network"`
			Chains   []string `json:"chains"`
			Rule     string   `json:"rule"`
			Upload   int64    `json:"upload"`
			Download int64    `json:"download"`
			Start    string   `json:"start"`
			Metadata struct {
				Host      string `json:"host"`
				SniffHost string `json:"sniffHost"`
				DstIP     string `json:"destinationIP"`
				DstPort   int    `json:"destinationPort,string"`
				SrcIP     string `json:"sourceIP"`
				SrcPort   int    `json:"sourcePort,string"`
				Process   string `json:"process"`
			} `json:"metadata"`
		} `json:"connections"`
	}
	traffic, _ := a.fetchTraffic()
	if err := a.apiRequest(http.MethodGet, "/connections", nil, &raw); err != nil {
		return ConnectionSnapshot{}, err
	}
	if raw.Memory == 0 {
		raw.Memory = a.coreMemoryUsage()
	}
	now := time.Now()
	a.mu.Lock()
	previousSamples := make(map[string]connectionSample, len(a.connectionSamples))
	for id, sample := range a.connectionSamples {
		previousSamples[id] = sample
	}
	nextSamples := make(map[string]connectionSample, len(raw.Connections))
	a.mu.Unlock()
	rows := make([]ConnectionRow, 0, len(raw.Connections))
	for _, c := range raw.Connections {
		address := firstNonEmpty(c.Metadata.Host, c.Metadata.SniffHost, c.Metadata.DstIP)
		if address == "" {
			address = c.Metadata.DstIP
		}
		if c.Metadata.DstPort > 0 {
			address = fmt.Sprintf("%s:%d", address, c.Metadata.DstPort)
		}
		source := c.Metadata.SrcIP
		if source != "" && c.Metadata.SrcPort > 0 {
			source = fmt.Sprintf("%s:%d", source, c.Metadata.SrcPort)
		}
		var uploadSpeed int64
		var downloadSpeed int64
		if previous, ok := previousSamples[c.ID]; ok {
			elapsed := now.Sub(previous.At).Seconds()
			if elapsed > 0 {
				uploadSpeed = int64(math.Max(0, float64(c.Upload-previous.Row.Upload)/elapsed))
				downloadSpeed = int64(math.Max(0, float64(c.Download-previous.Row.Download)/elapsed))
			}
		}
		row := ConnectionRow{
			ID:            c.ID,
			Network:       c.Network,
			Address:       address,
			DestinationIP: c.Metadata.DstIP,
			Source:        source,
			Process:       c.Metadata.Process,
			Rule:          c.Rule,
			Chains:        strings.Join(c.Chains, " / "),
			Upload:        c.Upload,
			Download:      c.Download,
			UploadSpeed:   uploadSpeed,
			DownloadSpeed: downloadSpeed,
			Start:         c.Start,
		}
		nextSamples[c.ID] = connectionSample{Row: row, At: now}
		rows = append(rows, row)
	}
	a.mu.Lock()
	for id, sample := range previousSamples {
		if _, ok := nextSamples[id]; ok {
			continue
		}
		row := sample.Row
		row.ClosedAt = now.Unix()
		a.closedConnections = append([]ConnectionRow{row}, a.closedConnections...)
	}
	if len(a.closedConnections) > 500 {
		a.closedConnections = append([]ConnectionRow(nil), a.closedConnections[:500]...)
	}
	closed := append([]ConnectionRow(nil), a.closedConnections...)
	a.connectionSamples = nextSamples
	a.mu.Unlock()
	return ConnectionSnapshot{
		UploadTotal:   raw.UploadTotal,
		DownloadTotal: raw.DownloadTotal,
		Memory:        raw.Memory,
		UploadSpeed:   traffic.Up,
		DownloadSpeed: traffic.Down,
		Connections:   rows,
		Closed:        closed,
	}, nil
}

func (a *App) CloseConnection(id string) error {
	return a.apiRequest(http.MethodDelete, "/connections/"+url.PathEscape(id), nil, nil)
}

func (a *App) CloseAllConnections() error {
	return a.apiRequest(http.MethodDelete, "/connections", nil, nil)
}

func (a *App) fetchTraffic() (TrafficSnapshot, bool) {
	var traffic TrafficSnapshot
	if err := a.apiRequest(http.MethodGet, "/traffic", nil, &traffic); err != nil {
		return traffic, false
	}
	return traffic, true
}

func (a *App) applyRuntimeSettings(settings Settings) error {
	if a.isEmbeddedCoreRunning() {
		a.applyEmbeddedRuntimeSettings(settings)
		return nil
	}
	body := map[string]any{
		"allow-lan": settings.AllowLan,
		"mode":      settings.Mode,
		"log-level": normalizeLogLevel(settings.LogLevel),
		"tun":       tunConfigMap(settings),
	}
	if name := strings.TrimSpace(settings.TunInterface); name != "" {
		body["interface-name"] = name
	}
	if err := a.apiRequest(http.MethodPatch, "/configs", body, nil); err != nil {
		return err
	}
	return nil
}

func tunConfigMap(settings Settings) map[string]any {
	config := map[string]any{
		"enable":                   settings.TunEnabled,
		"stack":                    normalizedTunStack(settings.TunStack),
		"dns-hijack":               nonEmptyStrings(settings.TunDNSHijack),
		"auto-route":               settings.TunAutoRoute,
		"auto-redirect":            settings.TunAutoRedirect,
		"auto-detect-interface":    settings.TunAutoDetect,
		"strict-route":             settings.TunStrictRoute,
		"endpoint-independent-nat": settings.TunEINAT,
	}
	addOptionalString(config, "device", settings.TunDevice)
	addOptionalInt(config, "mtu", settings.TunMTU)
	addOptionalBool(config, "gso", settings.TunGSO)
	addOptionalInt(config, "gso-max-size", settings.TunGSOMaxSize)
	addOptionalString(config, "inet6-address", settings.TunInet6Address)
	addOptionalInt(config, "udp-timeout", settings.TunUDPTimeout)
	addOptionalInt(config, "iproute2-table-index", settings.TunIPRoute2Table)
	addOptionalInt(config, "iproute2-rule-index", settings.TunIPRoute2Rule)
	addOptionalStringSlice(config, "route-address-set", settings.TunRouteSet)
	addOptionalStringSlice(config, "route-exclude-address-set", settings.TunRouteExcludeSet)
	addOptionalStringSlice(config, "route-address", settings.TunRouteAddress)
	addOptionalStringSlice(config, "route-exclude-address", settings.TunRouteExclude)
	includeIF := nonEmptyStrings(settings.TunIncludeIF)
	if len(includeIF) == 0 && strings.TrimSpace(settings.TunInterface) != "" {
		includeIF = []string{strings.TrimSpace(settings.TunInterface)}
	}
	addOptionalStringSlice(config, "include-interface", includeIF)
	if len(includeIF) == 0 {
		addOptionalStringSlice(config, "exclude-interface", settings.TunExcludeIF)
	}
	addOptionalIntSlice(config, "include-uid", settings.TunIncludeUID)
	addOptionalStringSlice(config, "include-uid-range", settings.TunIncludeUIDRange)
	addOptionalIntSlice(config, "exclude-uid", settings.TunExcludeUID)
	addOptionalStringSlice(config, "exclude-uid-range", settings.TunExcludeUIDRange)
	addOptionalIntSlice(config, "include-android-user", settings.TunIncludeAndroid)
	addOptionalStringSlice(config, "include-package", settings.TunIncludePackage)
	addOptionalStringSlice(config, "exclude-package", settings.TunExcludePackage)
	addOptionalStringSlice(config, "inet4-route-address", settings.TunInet4Route)
	addOptionalStringSlice(config, "inet6-route-address", settings.TunInet6Route)
	addOptionalStringSlice(config, "inet4-route-exclude-address", settings.TunInet4RouteExclude)
	addOptionalStringSlice(config, "inet6-route-exclude-address", settings.TunInet6RouteExclude)
	return config
}

func normalizedTunStack(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "system", "gvisor", "mixed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "mixed"
	}
}

func addOptionalString(config map[string]any, key string, value string) {
	if value = strings.TrimSpace(value); value != "" {
		config[key] = value
	}
}

func addOptionalInt(config map[string]any, key string, value int) {
	if value > 0 {
		config[key] = value
	}
}

func addOptionalBool(config map[string]any, key string, value bool) {
	if value {
		config[key] = true
	}
}

func addOptionalStringSlice(config map[string]any, key string, values []string) {
	if out := nonEmptyStrings(values); len(out) > 0 {
		config[key] = out
	}
}

func addOptionalIntSlice(config map[string]any, key string, values []int) {
	out := make([]int, 0, len(values))
	for _, value := range values {
		if value >= 0 {
			out = append(out, value)
		}
	}
	if len(out) > 0 {
		config[key] = out
	}
}

func nonEmptyStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func (a *App) isEmbeddedCoreRunning() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.embeddedCoreRunning
}

func (a *App) waitForAPIReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		a.mu.Lock()
		running := a.coreRunningLocked()
		a.mu.Unlock()
		if !running {
			if lastErr != nil {
				return fmt.Errorf("mihomo stopped before API became ready: %w", lastErr)
			}
			return errors.New("mihomo stopped before API became ready")
		}
		var version map[string]any
		if err := a.apiRequest(http.MethodGet, "/version", nil, &version); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(200 * time.Millisecond)
	}
	if lastErr != nil {
		return fmt.Errorf("mihomo API not ready: %w", lastErr)
	}
	return errors.New("mihomo API not ready")
}

func (a *App) GetLogs() []LogLine {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.recentLogsLocked(300)
}

func (a *App) OpenDataDirectory() error {
	switch goruntime.GOOS {
	case "windows":
		return exec.Command("explorer", a.dataDir).Start()
	case "darwin":
		return exec.Command("open", a.dataDir).Start()
	default:
		return exec.Command("xdg-open", a.dataDir).Start()
	}
}

func (a *App) OpenURL(target string) {
	if a.ctx != nil {
		wailsruntime.BrowserOpenURL(a.ctx, target)
	}
}

func (a *App) SelectBackgroundImage() (string, error) {
	if a.ctx == nil {
		return "", errors.New("app not ready")
	}
	path, err := wailsruntime.OpenFileDialog(a.ctx, wailsruntime.OpenDialogOptions{
		Title: "选择背景图片",
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "Images", Pattern: "*.png;*.jpg;*.jpeg;*.webp;*.bmp;*.gif"},
		},
	})
	if err != nil || strings.TrimSpace(path) == "" {
		return path, err
	}
	return a.ImportBackgroundImage(path)
}

func (a *App) ImportBackgroundImage(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	data, contentType, err := readBackgroundImage(path)
	if err != nil {
		return "", err
	}
	exts, _ := mime.ExtensionsByType(contentType)
	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" && len(exts) > 0 {
		ext = exts[0]
	}
	if ext == "" {
		ext = ".img"
	}
	id := sanitizeFilename(fmt.Sprintf("%d%s", time.Now().UnixNano(), ext))
	target := filepath.Join(a.dataDir, "backgrounds", id)
	if err := os.WriteFile(target, data, 0o644); err != nil {
		return "", err
	}
	return filepath.Base(target), nil
}

func (a *App) ListBackgroundImages() ([]BackgroundImage, error) {
	entries, err := os.ReadDir(filepath.Join(a.dataDir, "backgrounds"))
	if err != nil {
		return nil, err
	}
	type item struct {
		entry os.DirEntry
		mod   time.Time
	}
	items := make([]item, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		items = append(items, item{entry: entry, mod: info.ModTime()})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].mod.Before(items[j].mod) })
	backgrounds := make([]BackgroundImage, 0, len(items))
	for _, item := range items {
		backgrounds = append(backgrounds, BackgroundImage{ID: item.entry.Name(), Name: fmt.Sprintf("背景%d", len(backgrounds)+1)})
	}
	return backgrounds, nil
}

func (a *App) DeleteBackgroundImage(id string) error {
	id = sanitizeFilename(strings.TrimSpace(id))
	if id == "" {
		return nil
	}
	if err := os.Remove(filepath.Join(a.dataDir, "backgrounds", id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	a.mu.Lock()
	if a.store.Settings.BackgroundPath == id {
		a.store.Settings.BackgroundPath = ""
		err := a.saveStoreLocked()
		a.mu.Unlock()
		return err
	}
	a.mu.Unlock()
	return nil
}

func (a *App) ReadBackgroundImageDataURL(id string) (string, error) {
	id = sanitizeFilename(strings.TrimSpace(id))
	if id == "" {
		return "", nil
	}
	data, contentType, err := readBackgroundImage(filepath.Join(a.dataDir, "backgrounds", id))
	if err != nil {
		return "", err
	}
	return "data:" + contentType + ";base64," + base64.StdEncoding.EncodeToString(data), nil
}

func readBackgroundImage(path string) ([]byte, string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, "", err
	}
	if info.IsDir() {
		return nil, "", errors.New("background image path is a directory")
	}
	if info.Size() > 20*1024*1024 {
		return nil, "", errors.New("background image must be 20MB or smaller")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	contentType := mime.TypeByExtension(strings.ToLower(filepath.Ext(path)))
	if !strings.HasPrefix(contentType, "image/") {
		contentType = http.DetectContentType(data)
	}
	if !strings.HasPrefix(contentType, "image/") {
		return nil, "", errors.New("background file is not an image")
	}
	return data, contentType, nil
}
func (a *App) downloadProfile(source string) ([]byte, http.Header, error) {
	a.mu.Lock()
	settings := a.store.Settings
	a.mu.Unlock()
	if parsed, err := url.Parse(source); err == nil && !settings.SubscriptionProxy && isGithubDownloadHost(parsed.Hostname()) {
		resp, err := a.githubRequest(http.MethodGet, source, nil, map[string]string{"Accept": "text/yaml, text/plain, application/octet-stream, */*"})
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			return nil, resp.Header, fmt.Errorf("subscription returned HTTP %d", resp.StatusCode)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 12*1024*1024))
		if err != nil {
			return nil, resp.Header, err
		}
		return body, resp.Header, nil
	}
	req, err := http.NewRequest(http.MethodGet, source, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", subscriptionUserAgent)
	req.Header.Set("Accept", "text/yaml, text/plain, application/octet-stream, */*")
	client := a.httpClient
	if settings.SubscriptionProxy {
		client = subscriptionProxyClient(settings)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, resp.Header, fmt.Errorf("subscription returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 12*1024*1024))
	if err != nil {
		return nil, resp.Header, err
	}
	return body, resp.Header, nil
}

func subscriptionProxyClient(settings Settings) *http.Client {
	proxyURL := &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", settings.MixedPort)}
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
}

func parseSubscriptionInfo(headers http.Header) SubscriptionInfo {
	info := SubscriptionInfo{
		RawUserInfo: strings.TrimSpace(headers.Get("subscription-userinfo")),
		UpdatedAt:   time.Now().Unix(),
	}
	for _, part := range strings.Split(info.RawUserInfo, ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		amount, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "upload":
			info.Upload = amount
		case "download":
			info.Download = amount
		case "total":
			info.Total = amount
		case "expire":
			info.Expire = amount
		}
	}
	if interval, err := strconv.Atoi(strings.TrimSpace(headers.Get("profile-update-interval"))); err == nil {
		info.UpdateInterval = interval
	}
	if !subscriptionInfoHasData(info) {
		info.UpdatedAt = 0
	}
	return info
}

func subscriptionInfoHasData(info SubscriptionInfo) bool {
	return info.RawUserInfo != "" || info.Total > 0 || info.Expire > 0 || info.UpdateInterval > 0
}

func (a *App) writeProfile(name, profileType, source string, body []byte, subscription SubscriptionInfo) (Profile, error) {
	id := fmt.Sprintf("%d", time.Now().UnixNano())
	path := filepath.Join(a.dataDir, "profiles", sanitizeFilename(id+"-"+name)+".yaml")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return Profile{}, err
	}
	profile := Profile{
		ID:           id,
		Name:         name,
		Type:         profileType,
		Source:       source,
		Path:         path,
		UpdatedAt:    time.Now().Unix(),
		Enabled:      true,
		Subscription: subscription,
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.store.Profiles = append(a.store.Profiles, profile)
	if a.store.ActiveProfileID == "" {
		a.store.ActiveProfileID = profile.ID
	}
	return profile, a.saveStoreLocked()
}

func (a *App) saveStoreLocked() error {
	data, err := json.MarshalIndent(a.store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(a.storePath, data, 0o644)
}

func (a *App) activeProfileLocked() (Profile, bool) {
	for _, profile := range a.store.Profiles {
		if profile.ID == a.store.ActiveProfileID {
			return profile, true
		}
	}
	if len(a.store.Profiles) > 0 {
		return a.store.Profiles[0], true
	}
	return Profile{}, false
}

func (a *App) activeProfileNameLocked() string {
	profile, ok := a.activeProfileLocked()
	if !ok {
		return ""
	}
	return profile.Name
}

func (a *App) profileByIDLocked(profileID string) (Profile, bool) {
	for _, profile := range a.store.Profiles {
		if profile.ID == profileID {
			return profile, true
		}
	}
	return Profile{}, false
}

func (a *App) coreRunningLocked() bool {
	return a.embeddedCoreRunning || a.serviceCoreRunning || (a.coreCmd != nil && a.coreCmd.Process != nil)
}

func (a *App) corePathExists(corePath string) bool {
	_, err := a.resolveCorePath(corePath)
	return err == nil
}

func (a *App) coreAvailable(settings Settings) bool {
	if settings.CoreMode == "service" && goruntime.GOOS == "windows" {
		return true
	}
	if settings.CoreMode != "custom" {
		return true
	}
	return a.corePathExists(settings.CorePath)
}

func coreModeImplementation(settings Settings) string {
	switch settings.CoreMode {
	case "custom":
		return "custom"
	case "service":
		// Legacy value: post-mergeSettings this should not survive, but keep
		// the safe mapping for users who reload a stale store.json.
		if goruntime.GOOS == "windows" && !appHasEmbeddedCore() {
			return "service-registered"
		}
		return "app"
	case "embedded", "":
		if appHasEmbeddedCore() {
			return "app"
		}
		if goruntime.GOOS != "windows" {
			return "external"
		}
		if settings.AutoStartService {
			return "service-registered"
		}
		if serviceHelperHasEmbeddedCore() {
			return "service-helper"
		}
		return "external-helper"
	}
	return "external"
}

func coreRunsAsRegisteredWindowsService(settings Settings) bool {
	return goruntime.GOOS == "windows" &&
		!appHasEmbeddedCore() &&
		(settings.CoreMode == "service" || (settings.CoreMode == "embedded" && settings.AutoStartService))
}

func (a *App) resolveCorePath(corePath string) (string, error) {
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
		return "", fmt.Errorf("mihomo core not found: %s", corePath)
	}

	for _, candidate := range a.corePathCandidates(corePath) {
		if path, ok := existingFile(candidate); ok {
			return path, nil
		}
	}
	return exec.LookPath(corePath)
}

func (a *App) corePathCandidates(coreName string) []string {
	names := uniqueStrings([]string{
		coreName,
		"mihomo.exe",
		"mihomo",
		"clash-meta.exe",
		"clash-meta",
		"clash.exe",
		"clash",
	})
	roots := []string{}
	if cwd, err := os.Getwd(); err == nil {
		roots = append(
			roots,
			filepath.Join(cwd, "build", "bin"),
			filepath.Join(cwd, "mihomo", "bin"),
			filepath.Join(cwd, "mihomo", "build", "bin"),
			cwd,
		)
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		roots = append(roots, exeDir, filepath.Join(exeDir, "build", "bin"))
	}
	roots = uniqueStrings(roots)

	candidates := make([]string, 0, len(names)*len(roots))
	for _, root := range roots {
		for _, name := range names {
			candidates = append(candidates, filepath.Join(root, name))
		}
	}
	return candidates
}

func existingFile(path string) (string, bool) {
	if path == "" {
		return "", false
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return "", false
	}
	if abs, err := filepath.Abs(path); err == nil {
		return abs, true
	}
	return path, true
}

func mergeRuntimeConfig(content []byte, settings Settings, controller string, customRules []CustomRule) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("parse profile YAML: %w", err)
	}
	root := yamlRootMapping(&doc)
	if root == nil {
		return nil, errors.New("profile YAML root must be a mapping")
	}
	setYAMLScalar(root, "mixed-port", settings.MixedPort)
	setYAMLScalar(root, "allow-lan", settings.AllowLan)
	setYAMLScalar(root, "mode", settings.Mode)
	setYAMLScalar(root, "log-level", normalizeLogLevel(settings.LogLevel))
	setYAMLScalar(root, "external-controller", controller)
	setYAMLScalar(root, "secret", settings.Secret)
	if strings.TrimSpace(settings.TunInet6Address) != "" {
		setYAMLScalar(root, "ipv6", true)
	}
	deleteYAMLKey(root, "interface-name")

	tun := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	writeTunYAML(tun, settings)
	setYAMLNode(root, "tun", tun)
	prependRules(root, customRules)

	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(&doc); err != nil {
		_ = encoder.Close()
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func writeTunYAML(tun *yaml.Node, settings Settings) {
	config := tunConfigMap(settings)
	keys := []string{
		"enable", "stack", "auto-route", "auto-redirect", "auto-detect-interface", "dns-hijack",
		"device", "mtu", "strict-route", "gso", "gso-max-size", "inet6-address", "udp-timeout",
		"iproute2-table-index", "iproute2-rule-index", "endpoint-independent-nat",
		"route-address-set", "route-exclude-address-set", "route-address", "route-exclude-address",
		"include-interface", "exclude-interface", "include-uid", "include-uid-range", "exclude-uid",
		"exclude-uid-range", "include-android-user", "include-package", "exclude-package",
		"inet4-route-address", "inet6-route-address", "inet4-route-exclude-address", "inet6-route-exclude-address",
	}
	for _, key := range keys {
		value, ok := config[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case []string:
			setYAMLStringSequence(tun, key, typed)
		case []int:
			setYAMLIntSequence(tun, key, typed)
		default:
			setYAMLScalar(tun, key, typed)
		}
	}
}

func normalizeCustomRuleRows(rules []CustomRule) []CustomRule {
	out := make([]CustomRule, 0, len(rules))
	for _, rule := range rules {
		rule.Type = strings.TrimSpace(strings.ToUpper(rule.Type))
		rule.Payload = strings.TrimSpace(rule.Payload)
		rule.Proxy = strings.TrimSpace(rule.Proxy)
		if rule.ID == "" {
			rule.ID = randomRuleID()
		}
		if rule.Type == "" || rule.Proxy == "" {
			continue
		}
		if rule.Type != "MATCH" && rule.Payload == "" {
			continue
		}
		out = append(out, rule)
	}
	return out
}

func customRuleString(rule CustomRule) string {
	parts := []string{strings.ToUpper(strings.TrimSpace(rule.Type))}
	if parts[0] != "MATCH" {
		parts = append(parts, strings.TrimSpace(rule.Payload))
	}
	parts = append(parts, strings.TrimSpace(rule.Proxy))
	if rule.NoResolve {
		parts = append(parts, "no-resolve")
	}
	return strings.Join(parts, ",")
}

func randomRuleID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func prependRules(root *yaml.Node, rules []CustomRule) {
	if len(rules) == 0 {
		return
	}
	ruleNode := yamlMappingValue(root, "rules")
	if ruleNode == nil || ruleNode.Kind != yaml.SequenceNode {
		ruleNode = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		setYAMLNode(root, "rules", ruleNode)
	}
	nodes := make([]*yaml.Node, 0, len(rules)+len(ruleNode.Content))
	for _, rule := range rules {
		nodes = append(nodes, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: customRuleString(rule)})
	}
	ruleNode.Content = append(nodes, ruleNode.Content...)
}

func yamlRootMapping(doc *yaml.Node) *yaml.Node {
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		return doc.Content[0]
	}
	if doc.Kind == yaml.MappingNode {
		return doc
	}
	return nil
}

func yamlMappingValue(mapping *yaml.Node, key string) *yaml.Node {
	index := yamlKeyIndex(mapping, key)
	if index < 0 {
		return nil
	}
	return mapping.Content[index+1]
}

func yamlScalarString(node *yaml.Node) string {
	if node == nil || node.Kind != yaml.ScalarNode {
		return ""
	}
	return node.Value
}

func setYAMLScalar(mapping *yaml.Node, key string, value any) {
	setYAMLNode(mapping, key, yamlScalar(value))
}

func setYAMLStringSequence(mapping *yaml.Node, key string, values []string) {
	node := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, value := range values {
		node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
	}
	setYAMLNode(mapping, key, node)
}

func setYAMLIntSequence(mapping *yaml.Node, key string, values []int) {
	node := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, value := range values {
		node.Content = append(node.Content, yamlScalar(value))
	}
	setYAMLNode(mapping, key, node)
}

func setYAMLNode(mapping *yaml.Node, key string, value *yaml.Node) {
	index := yamlKeyIndex(mapping, key)
	if index >= 0 {
		mapping.Content[index+1] = value
		return
	}
	mapping.Content = append(mapping.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
}

func deleteYAMLKey(mapping *yaml.Node, key string) {
	index := yamlKeyIndex(mapping, key)
	if index < 0 {
		return
	}
	mapping.Content = append(mapping.Content[:index], mapping.Content[index+2:]...)
}

func yamlKeyIndex(mapping *yaml.Node, key string) int {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return -1
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return i
		}
	}
	return -1
}

func yamlScalar(value any) *yaml.Node {
	node := &yaml.Node{Kind: yaml.ScalarNode}
	switch typed := value.(type) {
	case bool:
		node.Tag = "!!bool"
		if typed {
			node.Value = "true"
		} else {
			node.Value = "false"
		}
	case int:
		node.Tag = "!!int"
		node.Value = fmt.Sprintf("%d", typed)
	case string:
		node.Tag = "!!str"
		node.Value = typed
	default:
		node.Tag = "!!str"
		node.Value = fmt.Sprintf("%v", typed)
	}
	return node
}

func (a *App) buildRuntimeConfig(profile Profile, settings Settings) (string, error) {
	content, err := os.ReadFile(profile.Path)
	if err != nil {
		return "", err
	}
	controller := "127.0.0.1:9090"
	if parsed, err := url.Parse(settings.ApiBase); err == nil && parsed.Host != "" {
		controller = parsed.Host
	}
	customRules, err := a.readProfileCustomRules(profile)
	if err != nil {
		return "", err
	}
	merged, err := mergeRuntimeConfig(content, settings, controller, customRules)
	if err != nil {
		return "", err
	}
	runtimePath := filepath.Join(a.dataDir, "pulse-runtime.yaml")
	return runtimePath, os.WriteFile(runtimePath, merged, 0o644)
}

func (a *App) apiRequest(method, path string, body any, out any) error {
	a.mu.Lock()
	settings := a.store.Settings
	a.mu.Unlock()
	base := strings.TrimRight(settings.ApiBase, "/")
	if base == "" {
		base = defaultSettings().ApiBase
	}
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, base+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if settings.Secret != "" {
		req.Header.Set("Authorization", "Bearer "+settings.Secret)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("mihomo API %s returned %d: %s", path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out == nil {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (a *App) scanCoreOutput(reader io.Reader, level string) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		a.appendDataLog("mihomo.log", level, line)
		a.appendLog(level, line)
	}
}

func (a *App) appendLog(level, message string) {
	a.appendDataLog("app.log", level, message)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.logLines = append(a.logLines, LogLine{Time: time.Now().Unix(), Level: level, Message: message})
	if len(a.logLines) > 500 {
		a.logLines = append([]LogLine(nil), a.logLines[len(a.logLines)-500:]...)
	}
}

func (a *App) appendDataLog(filename string, level string, message string) {
	if a.dataDir == "" {
		return
	}
	logDir := filepath.Join(a.dataDir, "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return
	}
	line := fmt.Sprintf("%s [%s] %s\n", time.Now().Format(time.RFC3339), level, message)
	file, err := os.OpenFile(filepath.Join(logDir, filename), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = file.WriteString(line)
}

func (a *App) recentLogsLocked(limit int) []LogLine {
	if len(a.logLines) <= limit {
		return append([]LogLine(nil), a.logLines...)
	}
	return append([]LogLine(nil), a.logLines[len(a.logLines)-limit:]...)
}

func inferProfileName(provided string, source string, headers http.Header, body []byte) string {
	candidates := []string{
		provided,
		headers.Get("profile-title"),
		filenameFromDisposition(headers.Get("content-disposition")),
		yamlTitle(body),
		filenameFromURL(source),
		hostFromURL(source),
		"Remote Profile",
	}
	for _, candidate := range candidates {
		if name := cleanProfileName(candidate); name != "" {
			return name
		}
	}
	return "Remote Profile"
}

func filenameFromDisposition(disposition string) string {
	if disposition == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(disposition)
	if err != nil {
		return ""
	}
	return firstNonEmpty(params["filename*"], params["filename"])
}

func filenameFromURL(source string) string {
	parsed, err := url.Parse(source)
	if err != nil {
		return ""
	}
	for _, key := range []string{"name", "title", "filename", "file"} {
		if value := parsed.Query().Get(key); value != "" {
			return value
		}
	}
	return pathBaseName(parsed.Path)
}

func hostFromURL(source string) string {
	parsed, err := url.Parse(source)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func yamlTitle(body []byte) string {
	limit := 4096
	if len(body) < limit {
		limit = len(body)
	}
	for _, line := range strings.Split(string(body[:limit]), "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		for _, prefix := range []string{"name:", "profile:", "profile-name:", "title:"} {
			if strings.HasPrefix(lower, prefix) {
				return strings.TrimSpace(line[len(prefix):])
			}
		}
	}
	return ""
}

func pathBaseName(path string) string {
	base := filepath.Base(strings.ReplaceAll(path, "\\", "/"))
	if base == "." || base == "/" {
		return ""
	}
	return base
}

func cleanProfileName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if decoded, err := url.QueryUnescape(value); err == nil {
		value = decoded
	}
	if decoded, err := decodeBase64Text(value); err == nil && decoded != "" {
		value = decoded
	}
	value = strings.Trim(value, `"' `)
	value = pathBaseName(value)
	ext := strings.ToLower(filepath.Ext(value))
	if ext == ".yaml" || ext == ".yml" || ext == ".txt" || ext == ".conf" {
		value = strings.TrimSuffix(value, filepath.Ext(value))
	}
	value = sanitizeFilename(value)
	return strings.Trim(value, ".-_ ")
}

func decodeBase64Text(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value)%4 != 0 {
		return "", errors.New("not base64 text")
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	text := strings.TrimSpace(string(decoded))
	if text == "" || strings.ContainsRune(text, '\x00') || !utf8.ValidString(text) {
		return "", errors.New("not text")
	}
	return text, nil
}

func isGeneratedProfileName(name string, id string) bool {
	name = strings.TrimSpace(name)
	return name == "" || name == "Remote Profile" || name == id
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func sanitizeFilename(name string) string {
	replacer := strings.NewReplacer("\\", "-", "/", "-", ":", "-", "*", "-", "?", "-", "\"", "-", "<", "-", ">", "-", "|", "-")
	return strings.TrimSpace(replacer.Replace(name))
}

const defaultProfileYAML = `mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
external-controller: 127.0.0.1:9090
dns:
  enable: true
  listen: 127.0.0.1:1053
  enhanced-mode: fake-ip
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
proxies: []
proxy-groups:
  - name: GLOBAL
    type: select
    proxies:
      - DIRECT
rules:
  - MATCH,DIRECT
`
