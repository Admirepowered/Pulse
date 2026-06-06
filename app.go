package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
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
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
	"gopkg.in/yaml.v3"
)

type App struct {
	ctx        context.Context
	mu         sync.Mutex
	dataDir    string
	storePath  string
	store      Store
	coreCmd    *exec.Cmd
	startedAt  int64
	logLines   []LogLine
	httpClient *http.Client
}

type Store struct {
	ActiveProfileID string    `json:"activeProfileId"`
	Profiles        []Profile `json:"profiles"`
	Settings        Settings  `json:"settings"`
}

type Settings struct {
	CorePath    string         `json:"corePath"`
	ApiBase     string         `json:"apiBase"`
	Secret      string         `json:"secret"`
	MixedPort   int            `json:"mixedPort"`
	AllowLan    bool           `json:"allowLan"`
	Mode        string         `json:"mode"`
	TunEnabled  bool           `json:"tunEnabled"`
	SystemProxy bool           `json:"systemProxy"`
	Theme       string         `json:"theme"`
	AutoStart   bool           `json:"autoStart"`
	WebDAV      WebDAVSettings `json:"webdav"`
}

type WebDAVSettings struct {
	Enabled  bool   `json:"enabled"`
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Profile struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Source    string `json:"source"`
	Path      string `json:"path"`
	UpdatedAt int64  `json:"updatedAt"`
	Enabled   bool   `json:"enabled"`
}

type RuntimeState struct {
	Running       bool            `json:"running"`
	ApiReachable  bool            `json:"apiReachable"`
	CoreFound     bool            `json:"coreFound"`
	StartedAt     int64           `json:"startedAt"`
	DataDir       string          `json:"dataDir"`
	ActiveProfile string          `json:"activeProfile"`
	Profiles      []Profile       `json:"profiles"`
	Settings      Settings        `json:"settings"`
	Traffic       TrafficSnapshot `json:"traffic"`
	RecentLogs    []LogLine       `json:"recentLogs"`
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

type ProviderRow struct {
	Name      string `json:"name"`
	Vehicle   string `json:"vehicle"`
	UpdatedAt string `json:"updatedAt"`
	Proxies   int    `json:"proxies"`
}

type ConnectionRow struct {
	ID       string `json:"id"`
	Network  string `json:"network"`
	Address  string `json:"address"`
	Rule     string `json:"rule"`
	Chains   string `json:"chains"`
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
	Start    string `json:"start"`
}

const subscriptionUserAgent = "clash-verge/v2.5.2"

func NewApp() *App {
	return &App{
		httpClient: &http.Client{Timeout: 12 * time.Second},
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	if err := a.initStore(); err != nil {
		a.appendLog("error", err.Error())
		return
	}
	a.appendLog("info", "Pulse Wails client started")
}

func (a *App) shutdown(ctx context.Context) {
	_ = a.StopCore()
}

func (a *App) initStore() error {
	configDir, err := os.UserConfigDir()
	if err != nil {
		configDir = "."
	}
	a.dataDir = filepath.Join(configDir, "Pulse")
	a.storePath = filepath.Join(a.dataDir, "store.json")
	if err := os.MkdirAll(filepath.Join(a.dataDir, "profiles"), 0o755); err != nil {
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
	a.store.Settings = mergeSettings(a.store.Settings, defaultSettings())
	return nil
}

func defaultSettings() Settings {
	core := "mihomo"
	if goruntime.GOOS == "windows" {
		core = "mihomo.exe"
	}
	return Settings{
		CorePath:   core,
		ApiBase:    "http://127.0.0.1:9090",
		MixedPort:  7890,
		Mode:       "rule",
		Theme:      "system",
		TunEnabled: false,
	}
}

func mergeSettings(current, defaults Settings) Settings {
	if current.CorePath == "" {
		current.CorePath = defaults.CorePath
	}
	if current.ApiBase == "" {
		current.ApiBase = defaults.ApiBase
	}
	if current.MixedPort == 0 {
		current.MixedPort = defaults.MixedPort
	}
	if current.Mode == "" {
		current.Mode = defaults.Mode
	}
	if current.Theme == "" {
		current.Theme = defaults.Theme
	}
	return current
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
	a.mu.Unlock()

	traffic, apiOK := a.fetchTraffic()
	return RuntimeState{
		Running:       running,
		ApiReachable:  apiOK,
		CoreFound:     a.corePathExists(settings.CorePath),
		StartedAt:     startedAt,
		DataDir:       dataDir,
		ActiveProfile: active,
		Profiles:      profiles,
		Settings:      settings,
		Traffic:       traffic,
		RecentLogs:    logs,
	}
}

func (a *App) SaveSettings(settings Settings) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	settings = mergeSettings(settings, defaultSettings())
	a.store.Settings = settings
	return a.saveStoreLocked()
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
	profile, err := a.writeProfile(name, "subscription", source, body)
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
	return a.writeProfile(name, "local", "", []byte(content))
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
	defer a.mu.Unlock()
	if _, ok := a.profileByIDLocked(profileID); !ok {
		return errors.New("profile not found")
	}
	a.store.ActiveProfileID = profileID
	return a.saveStoreLocked()
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
	corePath, err := a.resolveCorePath(settings.CorePath)
	if err != nil {
		return err
	}
	runtimeConfig, err := a.buildRuntimeConfig(profile.Path, settings)
	if err != nil {
		return err
	}
	cmd := exec.Command(corePath, "-d", a.dataDir, "-f", runtimeConfig)
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
	a.appendLog("info", "mihomo started with profile: "+profile.Name)
	return nil
}

func (a *App) StopCore() error {
	a.mu.Lock()
	cmd := a.coreCmd
	a.coreCmd = nil
	a.startedAt = 0
	a.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	a.appendLog("info", "mihomo stop requested")
	return nil
}

func (a *App) RestartCore() error {
	if err := a.StopCore(); err != nil {
		return err
	}
	time.Sleep(400 * time.Millisecond)
	return a.StartCore()
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
	return a.apiRequest(http.MethodPut, "/proxies/"+url.PathEscape(group), body, nil)
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

func (a *App) FetchConnections() ([]ConnectionRow, error) {
	var raw struct {
		Connections []struct {
			ID       string   `json:"id"`
			Network  string   `json:"network"`
			Chains   []string `json:"chains"`
			Rule     string   `json:"rule"`
			Upload   int64    `json:"upload"`
			Download int64    `json:"download"`
			Start    string   `json:"start"`
			Metadata struct {
				Host    string `json:"host"`
				DstIP   string `json:"destinationIP"`
				DstPort int    `json:"destinationPort"`
			} `json:"metadata"`
		} `json:"connections"`
	}
	if err := a.apiRequest(http.MethodGet, "/connections", nil, &raw); err != nil {
		return nil, err
	}
	rows := make([]ConnectionRow, 0, len(raw.Connections))
	for _, c := range raw.Connections {
		address := c.Metadata.Host
		if address == "" {
			address = c.Metadata.DstIP
		}
		if c.Metadata.DstPort > 0 {
			address = fmt.Sprintf("%s:%d", address, c.Metadata.DstPort)
		}
		rows = append(rows, ConnectionRow{
			ID:       c.ID,
			Network:  c.Network,
			Address:  address,
			Rule:     c.Rule,
			Chains:   strings.Join(c.Chains, " / "),
			Upload:   c.Upload,
			Download: c.Download,
			Start:    c.Start,
		})
	}
	return rows, nil
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

func (a *App) downloadProfile(source string) ([]byte, http.Header, error) {
	req, err := http.NewRequest(http.MethodGet, source, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", subscriptionUserAgent)
	req.Header.Set("Accept", "text/yaml, text/plain, application/octet-stream, */*")
	resp, err := a.httpClient.Do(req)
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

func (a *App) writeProfile(name, profileType, source string, body []byte) (Profile, error) {
	id := fmt.Sprintf("%d", time.Now().UnixNano())
	path := filepath.Join(a.dataDir, "profiles", sanitizeFilename(id+"-"+name)+".yaml")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return Profile{}, err
	}
	profile := Profile{
		ID:        id,
		Name:      name,
		Type:      profileType,
		Source:    source,
		Path:      path,
		UpdatedAt: time.Now().Unix(),
		Enabled:   true,
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
	return a.coreCmd != nil && a.coreCmd.Process != nil
}

func (a *App) corePathExists(corePath string) bool {
	_, err := a.resolveCorePath(corePath)
	return err == nil
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
		roots = append(roots, cwd, filepath.Join(cwd, "build", "bin"))
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

func mergeRuntimeConfig(content []byte, settings Settings, controller string) ([]byte, error) {
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

func (a *App) buildRuntimeConfig(profilePath string, settings Settings) (string, error) {
	content, err := os.ReadFile(profilePath)
	if err != nil {
		return "", err
	}
	controller := "127.0.0.1:9090"
	if parsed, err := url.Parse(settings.ApiBase); err == nil && parsed.Host != "" {
		controller = parsed.Host
	}
	merged, err := mergeRuntimeConfig(content, settings, controller)
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
		a.appendLog(level, scanner.Text())
	}
}

func (a *App) appendLog(level, message string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.logLines = append(a.logLines, LogLine{Time: time.Now().Unix(), Level: level, Message: message})
	if len(a.logLines) > 500 {
		a.logLines = append([]LogLine(nil), a.logLines[len(a.logLines)-500:]...)
	}
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
