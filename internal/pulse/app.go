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
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	mihomoObservable "github.com/metacubex/mihomo/common/observable"
	mihomoConfig "github.com/metacubex/mihomo/config"
	mihomoConstant "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/hub/route"
	mihomoLog "github.com/metacubex/mihomo/log"
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
	mihomoLogSub         mihomoObservable.Subscription[mihomoLog.Event]
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
}

type Store struct {
	ActiveProfileID string    `json:"activeProfileId"`
	Profiles        []Profile `json:"profiles"`
	Settings        Settings  `json:"settings"`
}

type Settings struct {
	CorePath          string         `json:"corePath"`
	CoreMode          string         `json:"coreMode"`
	ApiBase           string         `json:"apiBase"`
	Secret            string         `json:"secret"`
	MixedPort         int            `json:"mixedPort"`
	AllowLan          bool           `json:"allowLan"`
	Mode              string         `json:"mode"`
	LogLevel          string         `json:"logLevel"`
	TunEnabled        bool           `json:"tunEnabled"`
	SystemProxy       bool           `json:"systemProxy"`
	DelayTestURL      string         `json:"delayTestUrl"`
	Language          string         `json:"language"`
	Theme             string         `json:"theme"`
	AutoStart         bool           `json:"autoStart"`
	AutoStartCore     bool           `json:"autoStartCore"`
	CloseBehavior     string         `json:"closeBehavior"`
	SubscriptionProxy bool           `json:"subscriptionProxy"`
	BackgroundPath    string         `json:"backgroundPath"`
	BackgroundBlur    int            `json:"backgroundBlur"`
	BackgroundOpacity int            `json:"backgroundOpacity"`
	WebDAV            WebDAVSettings `json:"webdav"`
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
	Running       bool            `json:"running"`
	ApiReachable  bool            `json:"apiReachable"`
	CoreFound     bool            `json:"coreFound"`
	Version       string          `json:"version"`
	BuildNumber   string          `json:"buildNumber"`
	StartedAt     int64           `json:"startedAt"`
	DataDir       string          `json:"dataDir"`
	ActiveProfile string          `json:"activeProfile"`
	Profiles      []Profile       `json:"profiles"`
	Settings      Settings        `json:"settings"`
	Traffic       TrafficSnapshot `json:"traffic"`
	RecentLogs    []LogLine       `json:"recentLogs"`
	Geodata       GeodataStatus   `json:"geodata"`
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
	Start         string `json:"start"`
}

type ConnectionSnapshot struct {
	UploadTotal   int64           `json:"uploadTotal"`
	DownloadTotal int64           `json:"downloadTotal"`
	Memory        uint64          `json:"memory"`
	UploadSpeed   int64           `json:"uploadSpeed"`
	DownloadSpeed int64           `json:"downloadSpeed"`
	Connections   []ConnectionRow `json:"connections"`
}

const (
	subscriptionUserAgent = "clash-verge/v2.5.2"
	defaultDelayTestURL   = "https://www.gstatic.com/generate_204"
)

var (
	AppVersion  = "P0"
	BuildNumber = "0"
)

func NewApp() *App {
	return &App{
		httpClient: &http.Client{Timeout: 12 * time.Second},
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
	a.updateTrayMenuState()
	a.startShowSignalWatcher()
	go func() {
		if err := a.EnsureGeodata(); err != nil {
			a.appendLog("error", "geodata download failed: "+err.Error())
		}
	}()
	if a.store.Settings.AutoStartCore {
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
	if !enabled {
		return
	}
	if err := setAutoStart(true); err != nil {
		a.appendLog("error", "auto-start path sync failed: "+err.Error())
		return
	}
	a.appendLog("info", "auto-start path synced to current executable")
}

func (a *App) Shutdown(ctx context.Context) {
	_ = a.StopCore()
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

func (a *App) MinimizeWindow() {
	wailsruntime.WindowHide(a.ctx)
}

func (a *App) ShowWindow() {
	if a.ctx == nil {
		return
	}
	wailsruntime.WindowUnminimise(a.ctx)
	wailsruntime.WindowShow(a.ctx)
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
	a.store.Settings = mergeSettings(a.store.Settings, defaultSettings())
	if missingAutoStartCore {
		a.store.Settings.AutoStartCore = true
	}
	if missingBackgroundOpacity {
		a.store.Settings.BackgroundOpacity = defaultSettings().BackgroundOpacity
	}
	if needsSave || missingAutoStartCore || missingBackgroundOpacity {
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
	if current.CloseBehavior == "" {
		current.CloseBehavior = defaults.CloseBehavior
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
		Running:       running,
		ApiReachable:  apiOK,
		CoreFound:     a.coreAvailable(settings),
		Version:       AppVersion,
		BuildNumber:   BuildNumber,
		StartedAt:     startedAt,
		DataDir:       dataDir,
		ActiveProfile: active,
		Profiles:      profiles,
		Settings:      settings,
		Traffic:       traffic,
		RecentLogs:    logs,
		Geodata:       geodata,
	}
}

func (a *App) SaveSettings(settings Settings) error {
	settings = mergeSettings(settings, defaultSettings())
	settings.LogLevel = normalizeLogLevel(settings.LogLevel)
	a.appendLog("info", fmt.Sprintf(
		"save settings requested: store=%s coreMode=%s autoStartCore=%t autoStart=%t systemProxy=%t allowLan=%t mixedPort=%d",
		a.storePath,
		settings.CoreMode,
		settings.AutoStartCore,
		settings.AutoStart,
		settings.SystemProxy,
		settings.AllowLan,
		settings.MixedPort,
	))
	a.mu.Lock()
	previous := a.store.Settings
	running := a.coreRunningLocked()
	requiresRestart := running && settingsRequireCoreRestart(previous, settings)
	requiresRuntimeApply := running && settingsRequireRuntimeApply(previous, settings)
	requiresSystemProxyApply := running || previous.SystemProxy != settings.SystemProxy || (settings.SystemProxy && previous.MixedPort != settings.MixedPort)
	a.store.Settings = settings
	err := a.saveStoreLocked()
	a.mu.Unlock()
	if err != nil {
		a.appendLog("error", "save settings store write failed: "+err.Error())
		return err
	}
	a.appendLog("info", "save settings store write complete")
	if err := setAutoStart(settings.AutoStart); err != nil {
		a.appendLog("error", "save settings auto-start apply failed: "+err.Error())
		return err
	}
	a.appendLog("info", fmt.Sprintf("save settings auto-start applied: enabled=%t", settings.AutoStart))
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

func settingsRequireCoreRestart(previous, next Settings) bool {
	return previous.CoreMode != next.CoreMode ||
		previous.CorePath != next.CorePath ||
		previous.ApiBase != next.ApiBase ||
		previous.Secret != next.Secret ||
		previous.MixedPort != next.MixedPort
}

func settingsRequireRuntimeApply(previous, next Settings) bool {
	return previous.AllowLan != next.AllowLan ||
		previous.Mode != next.Mode ||
		previous.LogLevel != next.LogLevel ||
		previous.TunEnabled != next.TunEnabled
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
		return a.RestartCore()
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
		return a.RestartCore()
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
	if err := a.EnsureGeodata(); err != nil {
		return err
	}
	runtimeConfig, err := a.buildRuntimeConfig(profile, settings)
	if err != nil {
		return err
	}
	if settings.CoreMode == "custom" {
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
	} else if err := a.startEmbeddedCore(runtimeConfig, settings); err != nil {
		return err
	}
	if err := a.waitForAPIReady(8 * time.Second); err != nil {
		if settings.CoreMode != "custom" {
			a.stopEmbeddedCore()
			a.mu.Lock()
			a.embeddedCoreRunning = false
			a.startedAt = 0
			a.mu.Unlock()
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
	settings := a.store.Settings
	a.coreCmd = nil
	a.embeddedCoreRunning = false
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
		if embedded {
			a.stopEmbeddedCore()
			a.appendLog("info", "mihomo stop requested")
		}
		a.updateTrayMenuState()
		return nil
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

func (a *App) startEmbeddedCore(runtimeConfig string, settings Settings) error {
	configBytes, err := os.ReadFile(runtimeConfig)
	if err != nil {
		return err
	}
	a.startMihomoLogSubscription()
	mihomoConstant.SetHomeDir(a.dataDir)
	mihomoConstant.SetConfig(runtimeConfig)
	if err := mihomoConfig.Init(mihomoConstant.Path.HomeDir()); err != nil {
		return err
	}
	route.SetEmbedMode(true)
	controller := "127.0.0.1:9090"
	if parsed, err := url.Parse(settings.ApiBase); err == nil && parsed.Host != "" {
		controller = parsed.Host
	}
	if err := hub.Parse(configBytes, hub.WithExternalController(controller), hub.WithSecret(settings.Secret)); err != nil {
		a.stopMihomoLogSubscription()
		return err
	}
	a.mu.Lock()
	a.embeddedCoreRunning = true
	a.startedAt = time.Now().Unix()
	a.mu.Unlock()
	a.appendLog("info", "embedded mihomo core started")
	return nil
}

func (a *App) stopEmbeddedCore() {
	route.ReCreateServer(&route.Config{})
	executor.Shutdown()
	a.stopMihomoLogSubscription()
}

func (a *App) startMihomoLogSubscription() {
	a.mu.Lock()
	if a.mihomoLogSub != nil {
		a.mu.Unlock()
		return
	}
	sub := mihomoLog.Subscribe()
	a.mihomoLogSub = sub
	a.mu.Unlock()
	go func() {
		for event := range sub {
			a.appendDataLog("mihomo.log", event.Type(), event.Payload)
			a.mu.Lock()
			a.logLines = append(a.logLines, LogLine{Time: time.Now().Unix(), Level: event.Type(), Message: event.Payload})
			if len(a.logLines) > 500 {
				a.logLines = append([]LogLine(nil), a.logLines[len(a.logLines)-500:]...)
			}
			a.mu.Unlock()
		}
	}()
}

func (a *App) stopMihomoLogSubscription() {
	a.mu.Lock()
	sub := a.mihomoLogSub
	a.mihomoLogSub = nil
	a.mu.Unlock()
	if sub != nil {
		mihomoLog.UnSubscribe(sub)
	}
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
	var raw struct {
		Providers map[string]struct {
			Name      string `json:"name"`
			Vehicle   string `json:"vehicleType"`
			UpdatedAt string `json:"updatedAt"`
			Proxies   []any  `json:"proxies"`
		} `json:"providers"`
	}
	if err := a.apiRequest(http.MethodGet, "/providers/proxies", nil, &raw); err != nil {
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
		rows = append(rows, ConnectionRow{
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
			Start:         c.Start,
		})
	}
	return ConnectionSnapshot{
		UploadTotal:   raw.UploadTotal,
		DownloadTotal: raw.DownloadTotal,
		Memory:        raw.Memory,
		UploadSpeed:   traffic.Up,
		DownloadSpeed: traffic.Down,
		Connections:   rows,
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
		"tun": map[string]any{
			"enable":                settings.TunEnabled,
			"stack":                 "mixed",
			"auto-route":            true,
			"auto-detect-interface": true,
		},
	}
	if err := a.apiRequest(http.MethodPatch, "/configs", body, nil); err != nil {
		return err
	}
	return nil
}

func (a *App) isEmbeddedCoreRunning() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.embeddedCoreRunning
}

func (a *App) applyEmbeddedRuntimeSettings(settings Settings) {
	if level, ok := mihomoLog.LogLevelMapping[normalizeLogLevel(settings.LogLevel)]; ok {
		mihomoLog.SetLevel(level)
	}
	a.appendLog("info", "embedded runtime settings applied locally; restart core if TUN or listener settings do not change immediately")
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
	return wailsruntime.OpenFileDialog(a.ctx, wailsruntime.OpenDialogOptions{
		Title: "选择背景图片",
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "Images", Pattern: "*.png;*.jpg;*.jpeg;*.webp;*.bmp;*.gif"},
		},
	})
}

func (a *App) ReadBackgroundImageDataURL(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", errors.New("background image path is a directory")
	}
	if info.Size() > 20*1024*1024 {
		return "", errors.New("background image must be 20MB or smaller")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	contentType := mime.TypeByExtension(strings.ToLower(filepath.Ext(path)))
	if !strings.HasPrefix(contentType, "image/") {
		contentType = http.DetectContentType(data)
	}
	if !strings.HasPrefix(contentType, "image/") {
		return "", errors.New("background file is not an image")
	}
	return "data:" + contentType + ";base64," + base64.StdEncoding.EncodeToString(data), nil
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
	return a.embeddedCoreRunning || (a.coreCmd != nil && a.coreCmd.Process != nil)
}

func (a *App) corePathExists(corePath string) bool {
	_, err := a.resolveCorePath(corePath)
	return err == nil
}

func (a *App) coreAvailable(settings Settings) bool {
	if settings.CoreMode != "custom" {
		return true
	}
	return a.corePathExists(settings.CorePath)
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

	tun := yamlMappingValue(root, "tun")
	if tun == nil || tun.Kind != yaml.MappingNode {
		tun = &yaml.Node{Kind: yaml.MappingNode}
		setYAMLNode(root, "tun", tun)
	}
	setYAMLScalar(tun, "enable", settings.TunEnabled)
	setYAMLScalar(tun, "stack", "mixed")
	setYAMLScalar(tun, "auto-route", true)
	setYAMLScalar(tun, "auto-detect-interface", true)
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

func setYAMLNode(mapping *yaml.Node, key string, value *yaml.Node) {
	index := yamlKeyIndex(mapping, key)
	if index >= 0 {
		mapping.Content[index+1] = value
		return
	}
	mapping.Content = append(mapping.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
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
