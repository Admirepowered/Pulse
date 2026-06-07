import {type CSSProperties, useCallback, useEffect, useMemo, useState} from 'react';
import {
    Activity,
    Bug,
    Cat,
    CircleStop,
    Cloud,
    Gauge,
    ListChecks,
    Maximize2,
    Minus,
    Network,
    Play,
    RefreshCcw,
    Save,
    Settings as SettingsIcon,
    X,
} from 'lucide-react';
import './App.css';
import {
    AddProfileFromURL,
    CloseAllConnections,
    CloseConnection,
    CloseWindow,
    DeleteProfile,
    FetchConnections,
    FetchProviders,
    FetchProxyGroups,
    FetchRules,
    GetLogs,
    GetSnapshot,
    ImportProfile,
    MinimizeWindow,
    Models,
    OpenDataDirectory,
    OpenURL,
    ReadBackgroundImageDataURL,
    ReadProfileContent,
    RestartCore,
    SaveProfileContent,
    SaveSettings,
    SelectBackgroundImage,
    SelectProxy,
    SetActiveProfile,
    StartCore,
    StopCore,
    UpdateProfile,
    UpdateProvider,
    WindowToggleMaximise,
} from './api';
import {noticeError, StatusPill} from './components/common';
import {ConnectionsPage} from './pages/ConnectionsPage';
import {DashboardPage} from './pages/DashboardPage';
import {LogsPage} from './pages/LogsPage';
import {ProfilesPage} from './pages/ProfilesPage';
import {ProxiesPage} from './pages/ProxiesPage';
import {RulesPage} from './pages/RulesPage';
import {SettingsPage} from './pages/SettingsPage';
import {
    emptySettings,
    emptySnapshot,
    emptyConnectionSnapshot,
    normalizeSettings,
    normalizeSnapshot,
    type ConnectionSnapshot,
    type ConnectionRow,
    type LogLine,
    type Profile,
    type ProviderRow,
    type ProxyGroup,
    type RuleRow,
    type RuntimeState,
    type Settings,
    type TabId,
} from './types';

const tabs: { id: TabId; label: string; icon: typeof Gauge }[] = [
    {id: 'dashboard', label: '总览', icon: Gauge},
    {id: 'proxies', label: '代理', icon: Network},
    {id: 'profiles', label: '配置', icon: Cloud},
    {id: 'rules', label: '规则', icon: ListChecks},
    {id: 'connections', label: '连接', icon: Activity},
    {id: 'logs', label: '日志', icon: Bug},
    {id: 'settings', label: '设置', icon: SettingsIcon},
];

function App() {
    const [tab, setTab] = useState<TabId>('dashboard');
    const [snapshot, setSnapshot] = useState<RuntimeState>(emptySnapshot);
    const [groups, setGroups] = useState<ProxyGroup[]>([]);
    const [rules, setRules] = useState<RuleRow[]>([]);
    const [providers, setProviders] = useState<ProviderRow[]>([]);
    const [connectionSnapshot, setConnectionSnapshot] = useState<ConnectionSnapshot>(emptyConnectionSnapshot);
    const [logs, setLogs] = useState<LogLine[]>([]);
    const [query, setQuery] = useState('');
    const [notice, setNotice] = useState('');
    const [busy, setBusy] = useState(false);
    const [profileName, setProfileName] = useState('');
    const [profileURL, setProfileURL] = useState('');
    const [importName, setImportName] = useState('');
    const [importContent, setImportContent] = useState('');
    const [editorProfile, setEditorProfile] = useState<Profile | null>(null);
    const [editorContent, setEditorContent] = useState('');
    const [settingsDraft, setSettingsDraft] = useState<Settings>(emptySettings);
    const [settingsDirty, setSettingsDirty] = useState(false);
    const [backgroundDataURL, setBackgroundDataURL] = useState('');

    const refreshSnapshot = useCallback(async () => {
        const next = await GetSnapshot() as RuntimeState;
        setSnapshot(normalizeSnapshot(next));
    }, []);

    const refreshPageData = useCallback(async (activeTab: TabId) => {
        if (activeTab === 'proxies') setGroups(await FetchProxyGroups() as ProxyGroup[]);
        if (activeTab === 'rules') setRules(await FetchRules() as RuleRow[]);
        if (activeTab === 'profiles') setProviders(await FetchProviders() as ProviderRow[]);
        if (activeTab === 'connections') setConnectionSnapshot(await FetchConnections() as ConnectionSnapshot);
        if (activeTab === 'logs') setLogs(await GetLogs() as LogLine[]);
    }, []);

    const run = useCallback(async (task: () => Promise<unknown>, message?: string) => {
        setBusy(true);
        setNotice('');
        try {
            await task();
            if (message) setNotice(message);
            await refreshSnapshot();
            await refreshPageData(tab);
        } catch (error) {
            setNotice(error instanceof Error ? error.message : String(error));
        } finally {
            setBusy(false);
        }
    }, [refreshPageData, refreshSnapshot, tab]);

    const saveSettings = useCallback(async (settings: Settings = settingsDraft) => {
        const next = normalizeSettings(settings);
        await SaveSettings(new Models.Settings(next));
        setSettingsDraft(next);
        setSnapshot((current) => normalizeSnapshot({...current, settings: next}));
        setSettingsDirty(false);
    }, [settingsDraft]);

    const applySettings = useCallback((settings: Settings) => {
        const next = normalizeSettings(settings);
        setSettingsDraft(next);
        setSettingsDirty(false);
        run(() => saveSettings(next), '设置已生效');
    }, [run, saveSettings]);

    useEffect(() => {
        refreshSnapshot().catch((error) => setNotice(String(error)));
    }, [refreshSnapshot]);

    useEffect(() => {
        if (!notice) return;
        const timer = window.setTimeout(() => setNotice(''), noticeError(notice) ? 6000 : 3500);
        return () => window.clearTimeout(timer);
    }, [notice]);

    useEffect(() => {
        if (!settingsDirty) setSettingsDraft(snapshot.settings);
    }, [settingsDirty, snapshot.settings]);

    useEffect(() => {
        const path = settingsDraft.backgroundPath;
        if (!path) {
            setBackgroundDataURL('');
            return;
        }
        let active = true;
        ReadBackgroundImageDataURL(path)
            .then((value) => {
                if (active) setBackgroundDataURL(value as string);
            })
            .catch((error) => setNotice(error instanceof Error ? error.message : String(error)));
        return () => {
            active = false;
        };
    }, [settingsDraft.backgroundPath]);

    useEffect(() => {
        refreshPageData(tab).catch(() => undefined);
        const timer = window.setInterval(() => {
            refreshSnapshot().catch(() => undefined);
            refreshPageData(tab).catch(() => undefined);
        }, tab === 'logs' || tab === 'connections' ? 2000 : 4500);
        return () => window.clearInterval(timer);
    }, [refreshPageData, refreshSnapshot, tab]);

    const filteredGroups = useMemo(() => {
        const value = query.trim().toLowerCase();
        if (!value) return groups;
        return groups
            .map((group) => ({
                ...group,
                nodes: group.nodes.filter((node) => `${group.name} ${node.name} ${node.type}`.toLowerCase().includes(value)),
            }))
            .filter((group) => group.nodes.length > 0 || group.name.toLowerCase().includes(value));
    }, [groups, query]);

    const filteredConnections = useMemo(() => {
        const value = query.trim().toLowerCase();
        const connections = connectionSnapshot.connections || [];
        if (!value) return connections;
        return connections.filter((item) => `${item.address} ${item.destinationIp} ${item.source} ${item.process} ${item.rule} ${item.chains}`.toLowerCase().includes(value));
    }, [connectionSnapshot.connections, query]);

    const openEditor = async (profile: Profile) => {
        setEditorProfile(profile);
        setEditorContent(await ReadProfileContent(profile.id) as string);
    };

    const chooseBackground = async () => {
        setBusy(true);
        setNotice('');
        try {
            const path = await SelectBackgroundImage() as string;
            if (!path) return;
            const dataURL = await ReadBackgroundImageDataURL(path) as string;
            const next = normalizeSettings({...settingsDraft, backgroundPath: path});
            setSettingsDraft(next);
            setSettingsDirty(false);
            setBackgroundDataURL(dataURL);
            await saveSettings(next);
            setNotice('背景已更新');
            await refreshSnapshot();
        } catch (error) {
            setNotice(error instanceof Error ? error.message : String(error));
        } finally {
            setBusy(false);
        }
    };

    const clearBackground = () => {
        setBackgroundDataURL('');
        applySettings({...settingsDraft, backgroundPath: ''});
    };

    const backgroundStyle = {
        backgroundImage: backgroundDataURL ? `url(${JSON.stringify(backgroundDataURL)})` : 'none',
        filter: `blur(${Math.max(0, Math.min(40, settingsDraft.backgroundBlur || 0))}px)`,
    } as CSSProperties;

    return (
        <main className={backgroundDataURL ? 'shell hasBackground' : 'shell'}>
            <div className="backgroundLayer" aria-hidden="true" style={backgroundStyle}/>
            <div className="backgroundOverlay" aria-hidden="true"/>
            <aside className="sidebar">
                <div className="brand">
                    <Cat size={28}/>
                    <div>
                        <strong>Pulse</strong>
                        <span>mihomo</span>
                    </div>
                </div>
                <nav>
                    {tabs.map((item) => {
                        const Icon = item.icon;
                        return (
                            <button className={tab === item.id ? 'active' : ''} key={item.id} onClick={() => setTab(item.id)}>
                                <Icon size={18}/>
                                <span>{item.label}</span>
                            </button>
                        );
                    })}
                </nav>
                <div className="sidebarFooter">
                    <StatusPill ok={snapshot.running} label={snapshot.running ? '核心运行中' : '核心已停止'}/>
                    <StatusPill ok={snapshot.apiReachable} label={snapshot.apiReachable ? 'API 已连接' : 'API 未连接'}/>
                </div>
            </aside>

            <section className="workspace">
                <header className="topbar">
                    <div className="topbarTitle">
                        <h1>{tabs.find((item) => item.id === tab)?.label}</h1>
                        <p>{snapshot.activeProfile || 'Direct'}</p>
                    </div>
                    <div className="actions">
                        <button className="iconButton" title="刷新" disabled={busy} onClick={() => run(async () => refreshPageData(tab))}>
                            <RefreshCcw size={18}/>
                        </button>
                        {snapshot.running ? (
                            <button className="danger" disabled={busy} onClick={() => run(StopCore, '核心已停止')}>
                                <CircleStop size={17}/>停止
                            </button>
                        ) : (
                            <button className="primary" disabled={busy} onClick={() => run(StartCore, '核心已启动')}>
                                <Play size={17}/>启动
                            </button>
                        )}
                        <div className="windowControls" aria-label="窗口控制">
                            <button className="chromeButton" title="最小化" onClick={() => run(MinimizeWindow)}>
                                <Minus size={15}/>
                            </button>
                            <button className="chromeButton" title="最大化" onClick={WindowToggleMaximise}>
                                <Maximize2 size={14}/>
                            </button>
                            <button className="chromeButton close" title={snapshot.settings.closeBehavior === 'exit' ? '退出' : '隐藏到托盘'} onClick={() => run(CloseWindow)}>
                                <X size={15}/>
                            </button>
                        </div>
                    </div>
                </header>

                {notice && <div className={noticeError(notice) ? 'notice error' : 'notice'}>{notice}</div>}

                {tab === 'dashboard' && (
                    <DashboardPage
                        snapshot={snapshot}
                        onRestart={() => run(RestartCore, '核心已重启')}
                        onOpenDir={() => run(OpenDataDirectory)}
                        onOpenMihomo={() => run(() => OpenURL('https://github.com/MetaCubeX/mihomo/tree/Meta'))}
                    />
                )}

                {tab === 'proxies' && (
                    <ProxiesPage
                        groups={filteredGroups}
                        query={query}
                        onQueryChange={setQuery}
                        onSelect={(group, node) => run(() => SelectProxy(group, node), `${group} -> ${node}`)}
                    />
                )}

                {tab === 'profiles' && (
                    <ProfilesPage
                        snapshot={snapshot}
                        providers={providers}
                        profileName={profileName}
                        profileURL={profileURL}
                        importName={importName}
                        importContent={importContent}
                        onProfileNameChange={setProfileName}
                        onProfileURLChange={setProfileURL}
                        onImportNameChange={setImportName}
                        onImportContentChange={setImportContent}
                        onOpenGithub={() => run(() => OpenURL('https://github.com/Admirepowered/Pulse'))}
                        onActivate={(id) => run(() => SetActiveProfile(id), '已切换 Profile')}
                        onEdit={openEditor}
                        onUpdateProfile={(id) => run(() => UpdateProfile(id), 'Profile 已更新')}
                        onDeleteProfile={(id) => run(() => DeleteProfile(id), 'Profile 已删除')}
                        onUpdateProvider={(name) => run(() => UpdateProvider(name), 'Provider 已更新')}
                        onAddSubscription={() => run(async () => {
                            await AddProfileFromURL(profileName, profileURL);
                            setProfileName('');
                            setProfileURL('');
                        }, '订阅已添加')}
                        onImportProfile={() => run(async () => {
                            await ImportProfile(importName, importContent);
                            setImportName('');
                            setImportContent('');
                        }, 'Profile 已导入')}
                    />
                )}

                {tab === 'rules' && <RulesPage rules={rules}/>}

                {tab === 'connections' && (
                    <ConnectionsPage
                        snapshot={connectionSnapshot}
                        connections={filteredConnections}
                        query={query}
                        onQueryChange={setQuery}
                        onCloseAll={() => run(CloseAllConnections, '连接已清空')}
                        onClose={(id) => run(() => CloseConnection(id), '连接已断开')}
                    />
                )}

                {tab === 'logs' && <LogsPage logs={logs.length ? logs : snapshot.recentLogs}/>}

                {tab === 'settings' && (
                    <SettingsPage
                        settings={settingsDraft}
                        onChange={(settings) => {
                            setSettingsDraft(settings);
                            setSettingsDirty(true);
                        }}
                        onApply={applySettings}
                        onSave={() => run(() => saveSettings(), '设置已保存')}
                        onOpenDir={() => run(OpenDataDirectory)}
                        onChooseBackground={chooseBackground}
                        onClearBackground={clearBackground}
                    />
                )}
            </section>

            {editorProfile && (
                <div className="modalBackdrop">
                    <div className="modal">
                        <div className="panelHead">
                            <div>
                                <h2>{editorProfile.name}</h2>
                                <span>{editorProfile.path}</span>
                            </div>
                            <button className="iconButton" onClick={() => setEditorProfile(null)}>
                                <X size={18}/>
                            </button>
                        </div>
                        <textarea className="editor" value={editorContent} onChange={(event) => setEditorContent(event.target.value)} spellCheck={false}/>
                        <div className="modalActions">
                            <button onClick={() => setEditorProfile(null)}>取消</button>
                            <button className="primary" onClick={() => run(async () => {
                                await SaveProfileContent(editorProfile.id, editorContent);
                                setEditorProfile(null);
                            }, 'Profile 已保存')}>
                                <Save size={17}/>保存
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </main>
    );
}

export default App;
