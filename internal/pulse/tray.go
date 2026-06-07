package pulse

import (
	_ "embed"
	"strings"

	"github.com/getlantern/systray"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

const (
	maxTrayProfiles = 24
	maxTrayNodes    = 48
)

//go:embed assets/tray.ico
var trayIcon []byte

func StartTray(app *App) {
	app.startTray()
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
	systray.SetTitle("Pulse")
	systray.SetTooltip("Pulse mihomo")

	showItem := systray.AddMenuItem("显示 Pulse", "显示主窗口")
	a.watchTrayItem(showItem, func() {
		wailsruntime.WindowShow(a.ctx)
	})

	a.trayCoreItem = systray.AddMenuItem("启动核心", "启动或停止 mihomo 核心")
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

	a.trayStatusItem = systray.AddMenuItem("状态：读取中", "当前运行状态")
	a.trayStatusItem.Disable()
	systray.AddSeparator()

	profilesMenu := systray.AddMenuItem("订阅配置", "切换当前 Profile")
	for i := 0; i < maxTrayProfiles; i++ {
		item := profilesMenu.AddSubMenuItem("Profile", "切换 Profile")
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

	nodesMenu := systray.AddMenuItem("节点 Selector", "切换当前策略组节点")
	a.trayNodeStatusItem = nodesMenu.AddSubMenuItem("核心未运行", "当前节点组状态")
	a.trayNodeStatusItem.Disable()
	for i := 0; i < maxTrayNodes; i++ {
		item := nodesMenu.AddSubMenuItem("Node", "切换节点")
		item.Hide()
		a.trayNodeItems = append(a.trayNodeItems, item)
		index := i
		a.watchTrayItem(item, func() {
			a.trayMu.Lock()
			if index >= len(a.trayNodeNames) {
				a.trayMu.Unlock()
				return
			}
			group := a.trayNodeGroup
			node := a.trayNodeNames[index]
			a.trayMu.Unlock()
			if err := a.SelectProxy(group, node); err != nil {
				a.appendLog("error", "tray select node failed: "+err.Error())
			}
		})
	}

	refreshItem := systray.AddMenuItem("刷新托盘菜单", "刷新 Profile 和节点列表")
	a.watchTrayItem(refreshItem, func() {})

	systray.AddSeparator()
	quitItem := systray.AddMenuItem("退出 Pulse", "退出应用")
	a.watchTrayItem(quitItem, func() {
		a.quitApplication()
	})

	a.trayMu.Lock()
	a.trayReady = true
	a.trayMu.Unlock()
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
	activeProfileName := "Direct"
	for _, profile := range profiles {
		if profile.ID == activeProfileID {
			activeProfileName = profile.Name
			break
		}
	}
	a.mu.Unlock()

	if a.trayCoreItem != nil {
		if running {
			a.trayCoreItem.SetTitle("停止核心")
		} else {
			a.trayCoreItem.SetTitle("启动核心")
		}
	}
	if a.trayStatusItem != nil {
		if running {
			a.trayStatusItem.SetTitle("状态：核心运行中 · " + activeProfileName)
		} else {
			a.trayStatusItem.SetTitle("状态：核心已停止 · " + activeProfileName)
		}
	}

	a.updateTrayProfiles(profiles, activeProfileID)
	a.updateTrayNodes(running)
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
			prefix = "✓ "
		}
		item.SetTitle(prefix + truncateTrayLabel(profile.Name, 42))
		item.Show()
	}
	a.trayMu.Lock()
	a.trayProfileIDs = ids
	a.trayMu.Unlock()
}

func (a *App) updateTrayNodes(running bool) {
	if !running {
		a.setTrayNodeStatus("核心未运行")
		a.setTrayNodeChoices("", nil, "")
		return
	}
	groups, err := a.FetchProxyGroups()
	if err != nil {
		a.setTrayNodeStatus("节点读取失败")
		a.setTrayNodeChoices("", nil, "")
		return
	}
	group, ok := chooseTrayProxyGroup(groups)
	if !ok {
		a.setTrayNodeStatus("没有可选择的策略组")
		a.setTrayNodeChoices("", nil, "")
		return
	}
	a.setTrayNodeStatus("当前组：" + truncateTrayLabel(group.Name, 34))
	a.setTrayNodeChoices(group.Name, group.Nodes, group.Now)
}

func (a *App) setTrayNodeStatus(title string) {
	if a.trayNodeStatusItem != nil {
		a.trayNodeStatusItem.SetTitle(title)
	}
}

func (a *App) setTrayNodeChoices(groupName string, nodes []ProxyNode, current string) {
	names := make([]string, 0, min(len(nodes), maxTrayNodes))
	for i, item := range a.trayNodeItems {
		if i >= len(nodes) {
			item.Hide()
			continue
		}
		node := nodes[i]
		names = append(names, node.Name)
		prefix := "  "
		if node.Name == current {
			prefix = "✓ "
		}
		item.SetTitle(prefix + truncateTrayLabel(node.Name, 44))
		item.Show()
	}
	a.trayMu.Lock()
	a.trayNodeGroup = groupName
	a.trayNodeNames = names
	a.trayMu.Unlock()
}

func chooseTrayProxyGroup(groups []ProxyGroup) (ProxyGroup, bool) {
	if len(groups) == 0 {
		return ProxyGroup{}, false
	}
	preferred := []string{"global", "selector", "proxy", "节点", "选择"}
	for _, needle := range preferred {
		for _, group := range groups {
			if len(group.Nodes) == 0 {
				continue
			}
			if strings.Contains(strings.ToLower(group.Name), needle) || strings.Contains(group.Name, needle) {
				return group, true
			}
		}
	}
	for _, group := range groups {
		if len(group.Nodes) > 0 {
			return group, true
		}
	}
	return ProxyGroup{}, false
}

func truncateTrayLabel(value string, maxRunes int) string {
	runes := []rune(value)
	if len(runes) <= maxRunes {
		return value
	}
	return string(runes[:maxRunes-1]) + "…"
}
