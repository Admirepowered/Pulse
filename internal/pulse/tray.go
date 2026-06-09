//go:build !darwin
// +build !darwin

package pulse

import (
	_ "embed"
	"strings"
	"time"

	"github.com/getlantern/systray"
)

const (
	maxTrayProfiles      = 24
	maxTrayGroups        = 18
	maxTrayNodesPerGroup = 36
)

//go:embed assets/tray.ico
var trayIcon []byte

type trayMenuItem = systray.MenuItem

func StartTray(app *App) {
	app.startTray()
}

func quitTray() {
	systray.Quit()
}

func (a *App) startTray() {
	a.trayOnce.Do(func() {
		systray.Register(func() {
			a.setupTrayMenu()
			a.updateTrayMenuState()
			a.appendLog("info", "system tray registered")
		}, func() {
			a.appendLog("info", "system tray stopped")
		})
	})
}

func (a *App) setupTrayMenu() {
	systray.SetIcon(trayIcon)
	refreshTrayIconAfterShellSettles()
	systray.SetTitle("Pulse")
	systray.SetTooltip("Pulse mihomo")
	a.installTrayDoubleClickHandler()

	a.trayShowItem = systray.AddMenuItem("Pulse", "Pulse")
	a.watchTrayItem(a.trayShowItem, func() {
		a.ShowWindow()
	})

	a.trayCoreItem = systray.AddMenuItem("Core", "mihomo")
	a.watchTrayItem(a.trayCoreItem, func() {
		a.mu.Lock()
		running := a.coreRunningLocked()
		a.mu.Unlock()
		var err error
		if running {
			err = a.StopCore()
		} else {
			err = a.StartCore()
		}
		if err != nil {
			a.appendLog("error", "tray core action failed: "+err.Error())
		}
	})

	a.trayStatusItem = systray.AddMenuItem("Status", "Status")
	a.trayStatusItem.Disable()
	systray.AddSeparator()

	a.trayModeMenu = systray.AddMenuItem("Mode", "Mode")
	a.trayRuleModeItem = a.trayModeMenu.AddSubMenuItem("Rule", "Rule")
	a.trayGlobalModeItem = a.trayModeMenu.AddSubMenuItem("Global", "Global")
	a.trayDirectModeItem = a.trayModeMenu.AddSubMenuItem("Direct", "Direct")
	a.watchTrayItem(a.trayRuleModeItem, func() {
		if err := a.SetMode("rule"); err != nil {
			a.appendLog("error", "tray set rule mode failed: "+err.Error())
		}
	})
	a.watchTrayItem(a.trayGlobalModeItem, func() {
		if err := a.SetMode("global"); err != nil {
			a.appendLog("error", "tray set global mode failed: "+err.Error())
		}
	})
	a.watchTrayItem(a.trayDirectModeItem, func() {
		if err := a.SetMode("direct"); err != nil {
			a.appendLog("error", "tray set direct mode failed: "+err.Error())
		}
	})

	a.trayAllowLanItem = systray.AddMenuItem("Allow LAN", "Allow LAN")
	a.watchTrayItem(a.trayAllowLanItem, func() {
		a.mu.Lock()
		enabled := !a.store.Settings.AllowLan
		a.mu.Unlock()
		if err := a.SetAllowLan(enabled); err != nil {
			a.appendLog("error", "tray set allow lan failed: "+err.Error())
		}
	})
	a.traySystemProxyItem = systray.AddMenuItem("System Proxy", "System Proxy")
	a.watchTrayItem(a.traySystemProxyItem, func() {
		a.mu.Lock()
		enabled := !a.store.Settings.SystemProxy
		a.mu.Unlock()
		if err := a.SetSystemProxy(enabled); err != nil {
			a.appendLog("error", "tray set system proxy failed: "+err.Error())
		}
	})
	a.traySubProxyItem = systray.AddMenuItem("Proxy Updates", "Proxy Updates")
	a.watchTrayItem(a.traySubProxyItem, func() {
		a.mu.Lock()
		enabled := !a.store.Settings.SubscriptionProxy
		a.mu.Unlock()
		if err := a.SetSubscriptionProxy(enabled); err != nil {
			a.appendLog("error", "tray set subscription proxy failed: "+err.Error())
		}
	})
	a.trayAutoStartItem = systray.AddMenuItem("Auto Start", "Auto Start")
	a.watchTrayItem(a.trayAutoStartItem, func() {
		a.mu.Lock()
		enabled := !a.store.Settings.AutoStart
		a.mu.Unlock()
		if err := a.SetAutoStart(enabled); err != nil {
			a.appendLog("error", "tray set auto start failed: "+err.Error())
		}
	})
	systray.AddSeparator()

	a.trayProfilesMenu = systray.AddMenuItem("Profiles", "Profiles")
	for i := 0; i < maxTrayProfiles; i++ {
		item := a.trayProfilesMenu.AddSubMenuItem("Profile", "Profile")
		item.Hide()
		a.trayProfileItems = append(a.trayProfileItems, item)
		index := i
		a.watchTrayItem(item, func() {
			a.trayMu.Lock()
			if index >= len(a.trayProfileIDs) {
				a.trayMu.Unlock()
				return
			}
			id := a.trayProfileIDs[index]
			a.trayMu.Unlock()
			if err := a.SetActiveProfile(id); err != nil {
				a.appendLog("error", "tray switch profile failed: "+err.Error())
			}
		})
	}

	a.trayNodesMenu = systray.AddMenuItem("Nodes", "Nodes")
	a.trayNodeStatusItem = a.trayNodesMenu.AddSubMenuItem("Status", "Status")
	a.trayNodeStatusItem.Disable()
	for groupIndex := 0; groupIndex < maxTrayGroups; groupIndex++ {
		groupItem := a.trayNodesMenu.AddSubMenuItem("Group", "Group")
		a.trayNodeGroupItems = append(a.trayNodeGroupItems, groupItem)
		nodeItems := make([]*trayMenuItem, 0, maxTrayNodesPerGroup)
		for nodeIndex := 0; nodeIndex < maxTrayNodesPerGroup; nodeIndex++ {
			item := groupItem.AddSubMenuItem("Node", "Node")
			item.Hide()
			nodeItems = append(nodeItems, item)
			gi, ni := groupIndex, nodeIndex
			a.watchTrayItem(item, func() {
				a.trayMu.Lock()
				if gi >= len(a.trayNodeGroupNames) || gi >= len(a.trayNodeNamesByGroup) || ni >= len(a.trayNodeNamesByGroup[gi]) {
					a.trayMu.Unlock()
					return
				}
				group := a.trayNodeGroupNames[gi]
				node := a.trayNodeNamesByGroup[gi][ni]
				a.trayMu.Unlock()
				if err := a.SelectProxy(group, node); err != nil {
					a.appendLog("error", "tray select node failed: "+err.Error())
				}
			})
		}
		groupItem.Hide()
		a.trayNodeItems = append(a.trayNodeItems, nodeItems)
	}

	a.trayRefreshItem = systray.AddMenuItem("Refresh", "Refresh")
	a.watchTrayItem(a.trayRefreshItem, func() {})

	systray.AddSeparator()
	a.trayQuitItem = systray.AddMenuItem("Quit", "Quit")
	a.watchTrayItem(a.trayQuitItem, func() {
		a.quitApplication()
	})

	a.trayMu.Lock()
	a.trayReady = true
	a.trayMu.Unlock()
}

func refreshTrayIconAfterShellSettles() {
	for _, delay := range []time.Duration{250 * time.Millisecond, time.Second, 3 * time.Second, 8 * time.Second} {
		go func(delay time.Duration) {
			time.Sleep(delay)
			systray.SetIcon(trayIcon)
			systray.SetTooltip("Pulse mihomo")
		}(delay)
	}
}

func (a *App) watchTrayItem(item *systray.MenuItem, action func()) {
	go func() {
		for range item.ClickedCh {
			action()
			a.updateTrayMenuState()
		}
	}()
}

func (a *App) updateTrayMenuState() {
	a.trayMu.Lock()
	ready := a.trayReady
	a.trayMu.Unlock()
	if !ready {
		return
	}

	a.mu.Lock()
	running := a.coreRunningLocked()
	activeProfileID := a.store.ActiveProfileID
	profiles := append([]Profile(nil), a.store.Profiles...)
	settings := a.store.Settings
	labels := trayLabelsForLanguage(a.store.Settings.Language)
	activeProfileName := "Direct"
	for _, profile := range profiles {
		if profile.ID == activeProfileID {
			activeProfileName = profile.Name
			break
		}
	}
	a.mu.Unlock()

	if a.trayShowItem != nil {
		a.trayShowItem.SetTitle(labels.Show)
	}
	if a.trayCoreItem != nil {
		if running {
			a.trayCoreItem.SetTitle(labels.StopCore)
		} else {
			a.trayCoreItem.SetTitle(labels.StartCore)
		}
	}
	if a.trayStatusItem != nil {
		if running {
			a.trayStatusItem.SetTitle(labels.StatusRunning + " - " + activeProfileName)
		} else {
			a.trayStatusItem.SetTitle(labels.StatusStopped + " - " + activeProfileName)
		}
	}
	if a.trayProfilesMenu != nil {
		a.trayProfilesMenu.SetTitle(labels.Profiles)
	}
	if a.trayModeMenu != nil {
		a.trayModeMenu.SetTitle(labels.Mode)
	}
	setTrayModeTitle(a.trayRuleModeItem, labels.RuleMode, settings.Mode == "rule")
	setTrayModeTitle(a.trayGlobalModeItem, labels.GlobalMode, settings.Mode == "global")
	setTrayModeTitle(a.trayDirectModeItem, labels.DirectMode, settings.Mode == "direct")
	setTrayToggleTitle(a.trayAllowLanItem, labels.AllowLAN, settings.AllowLan)
	setTrayToggleTitle(a.traySystemProxyItem, labels.SystemProxy, settings.SystemProxy)
	setTrayToggleTitle(a.traySubProxyItem, labels.SubscriptionProxy, settings.SubscriptionProxy)
	setTrayToggleTitle(a.trayAutoStartItem, labels.AutoStart, settings.AutoStart)
	if a.trayNodesMenu != nil {
		a.trayNodesMenu.SetTitle(labels.Nodes)
	}
	if a.trayRefreshItem != nil {
		a.trayRefreshItem.SetTitle(labels.Refresh)
	}
	if a.trayQuitItem != nil {
		a.trayQuitItem.SetTitle(labels.Quit)
	}

	a.updateTrayProfiles(profiles, activeProfileID)
	a.updateTrayNodes(running, labels)
}

func (a *App) updateTrayProfiles(profiles []Profile, activeProfileID string) {
	ids := make([]string, 0, min(len(profiles), maxTrayProfiles))
	for i, item := range a.trayProfileItems {
		if i >= len(profiles) {
			item.Hide()
			continue
		}
		profile := profiles[i]
		ids = append(ids, profile.ID)
		prefix := "  "
		if profile.ID == activeProfileID {
			prefix = "* "
		}
		item.SetTitle(prefix + truncateTrayLabel(profile.Name, 42))
		item.Show()
	}
	a.trayMu.Lock()
	a.trayProfileIDs = ids
	a.trayMu.Unlock()
}

func (a *App) updateTrayNodes(running bool, labels trayLabels) {
	if !running {
		a.setTrayNodeStatus(labels.CoreStopped)
		a.setTrayNodeGroups(nil)
		return
	}
	groups, err := a.FetchProxyGroups()
	if err != nil {
		a.setTrayNodeStatus(labels.LoadFailed)
		a.setTrayNodeGroups(nil)
		return
	}
	groups = selectableTrayProxyGroups(groups)
	if len(groups) == 0 {
		a.setTrayNodeStatus(labels.NoGroups)
		a.setTrayNodeGroups(nil)
		return
	}
	a.setTrayNodeStatus(labels.SelectGroup)
	a.setTrayNodeGroups(groups)
}

func (a *App) setTrayNodeStatus(title string) {
	if a.trayNodeStatusItem != nil {
		a.trayNodeStatusItem.SetTitle(title)
	}
}

func (a *App) setTrayNodeGroups(groups []ProxyGroup) {
	groupNames := make([]string, 0, min(len(groups), maxTrayGroups))
	nodeNamesByGroup := make([][]string, 0, min(len(groups), maxTrayGroups))
	for groupIndex, groupItem := range a.trayNodeGroupItems {
		if groupIndex >= len(groups) {
			groupItem.Hide()
			for _, item := range a.trayNodeItems[groupIndex] {
				item.Hide()
			}
			continue
		}
		group := groups[groupIndex]
		groupNames = append(groupNames, group.Name)
		groupItem.SetTitle(truncateTrayLabel(group.Name, 32) + " -> " + truncateTrayLabel(group.Now, 28))
		groupItem.Show()

		nodeNames := make([]string, 0, min(len(group.Nodes), maxTrayNodesPerGroup))
		for nodeIndex, item := range a.trayNodeItems[groupIndex] {
			if nodeIndex >= len(group.Nodes) {
				item.Hide()
				continue
			}
			node := group.Nodes[nodeIndex]
			nodeNames = append(nodeNames, node.Name)
			prefix := "  "
			if node.Name == group.Now {
				prefix = "* "
			}
			item.SetTitle(prefix + truncateTrayLabel(node.Name, 44))
			item.Show()
		}
		nodeNamesByGroup = append(nodeNamesByGroup, nodeNames)
	}
	a.trayMu.Lock()
	a.trayNodeGroupNames = groupNames
	a.trayNodeNamesByGroup = nodeNamesByGroup
	a.trayMu.Unlock()
}

func selectableTrayProxyGroups(groups []ProxyGroup) []ProxyGroup {
	result := make([]ProxyGroup, 0, len(groups))
	for _, group := range groups {
		if len(group.Nodes) == 0 {
			continue
		}
		if isSelectorGroup(group) {
			result = append(result, group)
		}
	}
	if len(result) > 0 {
		return result
	}
	for _, group := range groups {
		if len(group.Nodes) > 0 {
			result = append(result, group)
		}
	}
	return result
}

func isSelectorGroup(group ProxyGroup) bool {
	kind := strings.ToLower(strings.TrimSpace(group.Type))
	name := strings.ToLower(group.Name)
	return strings.Contains(kind, "select") || strings.Contains(kind, "selector") || strings.Contains(name, "selector")
}

func truncateTrayLabel(value string, maxRunes int) string {
	runes := []rune(value)
	if len(runes) <= maxRunes {
		return value
	}
	return string(runes[:maxRunes-1]) + "..."
}

func setTrayModeTitle(item *trayMenuItem, label string, active bool) {
	if item == nil {
		return
	}
	prefix := "  "
	if active {
		prefix = "* "
	}
	item.SetTitle(prefix + label)
}

func setTrayToggleTitle(item *trayMenuItem, label string, enabled bool) {
	if item == nil {
		return
	}
	prefix := "[ ] "
	if enabled {
		prefix = "[x] "
	}
	item.SetTitle(prefix + label)
}

type trayLabels struct {
	Show              string
	StartCore         string
	StopCore          string
	StatusRunning     string
	StatusStopped     string
	Mode              string
	RuleMode          string
	GlobalMode        string
	DirectMode        string
	AllowLAN          string
	SystemProxy       string
	SubscriptionProxy string
	AutoStart         string
	Profiles          string
	Nodes             string
	Refresh           string
	Quit              string
	CoreStopped       string
	LoadFailed        string
	NoGroups          string
	SelectGroup       string
}

func trayLabelsForLanguage(language string) trayLabels {
	if language == "en" {
		return trayLabels{
			Show:              "Show Pulse",
			StartCore:         "Start Core",
			StopCore:          "Stop Core",
			StatusRunning:     "Status: core running",
			StatusStopped:     "Status: core stopped",
			Mode:              "Mode",
			RuleMode:          "Rule",
			GlobalMode:        "Global",
			DirectMode:        "Direct",
			AllowLAN:          "Allow LAN",
			SystemProxy:       "System Proxy",
			SubscriptionProxy: "Proxy Updates",
			AutoStart:         "Start on boot",
			Profiles:          "Profiles",
			Nodes:             "Nodes",
			Refresh:           "Refresh Tray",
			Quit:              "Quit Pulse",
			CoreStopped:       "Core stopped",
			LoadFailed:        "Failed to load nodes",
			NoGroups:          "No selectable groups",
			SelectGroup:       "Select group",
		}
	}
	return trayLabels{
		Show:              "显示 Pulse",
		StartCore:         "启动核心",
		StopCore:          "停止核心",
		StatusRunning:     "状态：核心运行中",
		StatusStopped:     "状态：核心已停止",
		Mode:              "模式",
		RuleMode:          "规则",
		GlobalMode:        "全局",
		DirectMode:        "直连",
		AllowLAN:          "允许局域网",
		SystemProxy:       "系统代理",
		SubscriptionProxy: "代理更新订阅",
		AutoStart:         "开机启动",
		Profiles:          "订阅配置",
		Nodes:             "节点选择",
		Refresh:           "刷新托盘",
		Quit:              "退出 Pulse",
		CoreStopped:       "核心已停止",
		LoadFailed:        "节点加载失败",
		NoGroups:          "没有可选分组",
		SelectGroup:       "选择分组",
	}
}
