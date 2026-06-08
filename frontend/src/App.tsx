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
    Shield,
    X,
} from 'lucide-react';
import './App.css';
import {
    AddProfileFromURL,
    ApplyUpdate,
    CheckForUpdates,
    CloseAllConnections,
    CloseConnection,
    CloseWindow,
    DeleteProfile,
    DeleteBackgroundImage,
    FetchConnections,
    FetchProviders,
    FetchProxyGroups,
    FetchRules,
    GetLogs,
    GetSnapshot,
    ImportProfileFromFile,
    ListBackgroundImages,
    ListNetworkInterfaces,
    MinimizeWindow,
    Models,
    OnFileDrop,
    OnFileDropOff,
    OpenDataDirectory,
    OpenURL,
    ReadBackgroundImageDataURL,
    ReadProfileContent,
    ReadProfileCustomRules,
    ReadProfileRulePolicies,
    RenameProfile,
    RelaunchAsAdministrator,
    RestartCore,
    SaveProfileContent,
    SaveProfileCustomRules,
    SaveSettings,
    SelectBackgroundImage,
    SelectProxy,
    SetActiveProfile,
    StartCore,
    StopCore,
    TestProxyGroup,
    TestProxyNode,
    UpdateProfile,
    UpdateProvider,
    WindowToggleMaximise,
} from './api';
import {formatBytes, noticeError, StatusPill} from './components/common';
import {ConnectionsPage} from './pages/ConnectionsPage';
import {CustomRulesEditor} from './components/CustomRulesEditor';
import {YamlEditor} from './components/YamlEditor';
import {DashboardPage} from './pages/DashboardPage';
import {LogsPage} from './pages/LogsPage';
import {ProfilesPage} from './pages/ProfilesPage';
import {ProxiesPage} from './pages/ProxiesPage';
import {RulesPage} from './pages/RulesPage';
import {SettingsPage} from './pages/SettingsPage';
import {getTranslator} from './i18n';
import {
    emptySettings,
    emptySnapshot,
    emptyConnectionSnapshot,
    normalizeSettings,
    normalizeSnapshot,
    type ConnectionSnapshot,
    type CustomRule,
    type BackgroundImage,
    type ConnectionRow,
    type LogLine,
    type NetworkInterface,
    type Profile,
    type ProviderRow,
    type ProxyGroup,
    type RuleRow,
    type RuntimeState,
    type Settings,
    type TabId,
    type UpdateInfo,
} from './types';

const tabs: { id: TabId; labelKey: Parameters<ReturnType<typeof getTranslator>>[0]; icon: typeof Gauge }[] = [
    {id: 'dashboard', labelKey: 'dashboard', icon: Gauge},
    {id: 'proxies', labelKey: 'proxies', icon: Network},
    {id: 'profiles', labelKey: 'profiles', icon: Cloud},
    {id: 'rules', labelKey: 'rules', icon: ListChecks},
    {id: 'connections', labelKey: 'connections', icon: Activity},
    {id: 'logs', labelKey: 'logs', icon: Bug},
    {id: 'settings', labelKey: 'settings', icon: SettingsIcon},
];

type InlineActionState = 'running' | 'done' | 'failed';

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
    const [profileURL, setProfileURL] = useState('');
    const [editorProfile, setEditorProfile] = useState<Profile | null>(null);
    const [editorContent, setEditorContent] = useState('');
    const [ruleEditorProfile, setRuleEditorProfile] = useState<Profile | null>(null);
    const [ruleEditorRules, setRuleEditorRules] = useState<CustomRule[]>([]);
    const [ruleEditorPolicies, setRuleEditorPolicies] = useState<string[]>([]);
    const [settingsDraft, setSettingsDraft] = useState<Settings>(emptySettings);
    const [settingsDirty, setSettingsDirty] = useState(false);
    const [backgroundDataURL, setBackgroundDataURL] = useState('');
    const [backgrounds, setBackgrounds] = useState<BackgroundImage[]>([]);
    const [networkInterfaces, setNetworkInterfaces] = useState<NetworkInterface[]>([]);
    const [sidebarFocused, setSidebarFocused] = useState(false);
    const [testingGroup, setTestingGroup] = useState('');
    const [proxyGroupStatus, setProxyGroupStatus] = useState<Record<string, InlineActionState>>({});
    const [profileUpdateStatus, setProfileUpdateStatus] = useState<Record<string, InlineActionState>>({});
    const [providerUpdateStatus, setProviderUpdateStatus] = useState<Record<string, InlineActionState>>({});
    const [profileDropActive, setProfileDropActive] = useState(false);
    const t = useMemo(() => getTranslator(settingsDraft.language || snapshot.settings.language), [settingsDraft.language, snapshot.settings.language]);
    const adminNotice = notice.includes('管理员') || notice.toLowerCase().includes('administrator');

    const refreshSnapshot = useCallback(async () => {
        const next = await GetSnapshot();
        setSnapshot(normalizeSnapshot(next as unknown as Partial<RuntimeState>));
    }, []);

    const refreshPageData = useCallback(async (activeTab: TabId) => {
        if (activeTab === 'dashboard') setConnectionSnapshot(await FetchConnections() as ConnectionSnapshot);
        if (activeTab === 'proxies') setGroups(await FetchProxyGroups() as ProxyGroup[]);
        if (activeTab === 'rules') setRules(await FetchRules() as RuleRow[]);
        if (activeTab === 'profiles') setProviders(await FetchProviders() as ProviderRow[]);
        if (activeTab === 'settings') {
            const [nextBackgrounds, nextInterfaces] = await Promise.all([
                ListBackgroundImages() as Promise<BackgroundImage[]>,
                ListNetworkInterfaces() as Promise<NetworkInterface[]>,
            ]);
            setBackgrounds(nextBackgrounds);
            setNetworkInterfaces(nextInterfaces);
        }
        if (activeTab === 'connections') setConnectionSnapshot(await FetchConnections() as ConnectionSnapshot);
        if (activeTab === 'logs') setLogs(await GetLogs() as LogLine[]);
    }, []);

    const run = useCallback(async (task: () => Promise<unknown>, message?: string) => {
        void message;
        setBusy(true);
        setNotice('');
        try {
            await task();
            await refreshSnapshot();
            await refreshPageData(tab);
            return true;
        } catch (error) {
            setNotice(error instanceof Error ? error.message : String(error));
            return false;
        } finally {
            setBusy(false);
        }
    }, [refreshPageData, refreshSnapshot, tab]);

    const promptUpdate = useCallback(async (manual = false) => {
        try {
            const info = await CheckForUpdates() as UpdateInfo;
            if (!info.available) {
                if (manual) setNotice(t('noUpdateAvailable'));
                return;
            }
            const message = `${t('updateAvailable')}: ${info.latestVersion}\n${info.assetName}\n\n${t('update')}?`;
            if (window.confirm(message)) {
                await run(ApplyUpdate);
            }
        } catch (error) {
            if (manual) setNotice(error instanceof Error ? error.message : String(error));
        }
    }, [run, t]);

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
        run(() => saveSettings(next), t('settingsApplied'));
    }, [run, saveSettings, t]);

    useEffect(() => {
        refreshSnapshot().catch((error) => setNotice(String(error)));
    }, [refreshSnapshot]);

    useEffect(() => {
        const timer = window.setTimeout(() => {
            promptUpdate(false).catch(() => undefined);
        }, 2500);
        return () => window.clearTimeout(timer);
    }, [promptUpdate]);

    useEffect(() => {
        if (!notice) return;
        const timer = window.setTimeout(() => setNotice(''), noticeError(notice) ? 6000 : 3500);
        return () => window.clearTimeout(timer);
    }, [notice]);

    useEffect(() => {
        if (!settingsDirty) setSettingsDraft(snapshot.settings);
    }, [settingsDirty, snapshot.settings]);

    useEffect(() => {
        const id = settingsDraft.backgroundPath;
        if (!id) {
            setBackgroundDataURL('');
            return;
        }
        let active = true;
        ReadBackgroundImageDataURL(id)
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
        }, tab === 'logs' || tab === 'connections' || tab === 'dashboard' ? 2000 : 4500);
        return () => window.clearInterval(timer);
    }, [refreshPageData, refreshSnapshot, tab]);

    useEffect(() => {
        if (tab !== 'profiles') {
            setProfileDropActive(false);
            return;
        }
        OnFileDrop((_x, _y, paths) => {
            const profilePath = paths.find((path) => /\.(ya?ml)$/i.test(path));
            if (!profilePath) {
                setNotice('Only YAML profiles can be imported');
                return;
            }
            setProfileDropActive(false);
            run(() => ImportProfileFromFile(profilePath), t('profileImported'));
        }, false);
        return () => OnFileDropOff();
    }, [run, t, tab]);

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

    const openRuleEditor = async (profile: Profile) => {
        setRuleEditorProfile(profile);
        const [rules, policies] = await Promise.all([
            ReadProfileCustomRules(profile.id),
            ReadProfileRulePolicies(profile.id),
        ]);
        setRuleEditorRules(rules as CustomRule[]);
        setRuleEditorPolicies(policies as string[]);
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
            setBackgrounds(await ListBackgroundImages() as BackgroundImage[]);
            await saveSettings(next);
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

    const deleteBackground = async (id: string) => {
        await run(async () => {
            await DeleteBackgroundImage(id);
            const next = settingsDraft.backgroundPath === id ? normalizeSettings({...settingsDraft, backgroundPath: ''}) : settingsDraft;
            if (next.backgroundPath !== settingsDraft.backgroundPath) {
                await saveSettings(next);
                setBackgroundDataURL('');
            }
            setBackgrounds(await ListBackgroundImages() as BackgroundImage[]);
        });
    };

    const testProxyGroup = async (group: string) => {
        setTestingGroup(group);
        setProxyGroupStatus((current) => ({...current, [group]: 'running'}));
        try {
            const ok = await run(() => TestProxyGroup(group));
            if (ok) {
                setProxyGroupStatus((current) => ({...current, [group]: 'done'}));
                window.setTimeout(() => setProxyGroupStatus((current) => {
                    const next = {...current};
                    if (next[group] === 'done') delete next[group];
                    return next;
                }), 1200);
            } else {
                setProxyGroupStatus((current) => ({...current, [group]: 'failed'}));
                window.setTimeout(() => setProxyGroupStatus((current) => {
                    const next = {...current};
                    if (next[group] === 'failed') delete next[group];
                    return next;
                }), 1400);
            }
        } finally {
            setTestingGroup('');
        }
    };

    const updateProfileInline = async (id: string) => {
        setProfileUpdateStatus((current) => ({...current, [id]: 'running'}));
        const ok = await run(() => UpdateProfile(id));
        if (ok) {
            setProfileUpdateStatus((current) => ({...current, [id]: 'done'}));
            window.setTimeout(() => setProfileUpdateStatus((current) => {
                const next = {...current};
                if (next[id] === 'done') delete next[id];
                return next;
            }), 1200);
        } else {
            setProfileUpdateStatus((current) => ({...current, [id]: 'failed'}));
            window.setTimeout(() => setProfileUpdateStatus((current) => {
                const next = {...current};
                if (next[id] === 'failed') delete next[id];
                return next;
            }), 1400);
        }
    };

    const updateProviderInline = async (name: string) => {
        setProviderUpdateStatus((current) => ({...current, [name]: 'running'}));
        const ok = await run(() => UpdateProvider(name));
        if (ok) {
            setProviderUpdateStatus((current) => ({...current, [name]: 'done'}));
            window.setTimeout(() => setProviderUpdateStatus((current) => {
                const next = {...current};
                if (next[name] === 'done') delete next[name];
                return next;
            }), 1200);
        } else {
            setProviderUpdateStatus((current) => ({...current, [name]: 'failed'}));
            window.setTimeout(() => setProviderUpdateStatus((current) => {
                const next = {...current};
                if (next[name] === 'failed') delete next[name];
                return next;
            }), 1400);
        }
    };

    const backgroundStyle = {
        backgroundImage: backgroundDataURL ? `url(${JSON.stringify(backgroundDataURL)})` : 'none',
        filter: `blur(${Math.max(0, Math.min(40, settingsDraft.backgroundBlur || 0))}px)`,
    } as CSSProperties;
    const surfaceAlpha = Math.max(0, Math.min(100, settingsDraft.backgroundOpacity ?? 62)) / 100;
    const shellStyle = {
        '--surface-alpha': `${surfaceAlpha}`,
        '--surface-soft-alpha': `${Math.max(.15, surfaceAlpha - .04)}`,
        '--surface-strong-alpha': `${Math.min(1, surfaceAlpha + .08)}`,
        '--surface-button-alpha': `${Math.max(.12, surfaceAlpha - .20)}`,
        '--surface-success-alpha': `${Math.min(1, surfaceAlpha + .06)}`,
        '--surface-danger-alpha': `${Math.min(1, surfaceAlpha + .10)}`,
    } as CSSProperties;
    const geodataVisible = snapshot.geodata.checking || (!snapshot.geodata.ready && Boolean(snapshot.geodata.message));
    const geodataProgress = snapshot.geodata.total > 0
        ? Math.min(100, Math.max(0, (snapshot.geodata.downloaded / snapshot.geodata.total) * 100))
        : 0;

    return (
        <main className={backgroundDataURL ? 'shell hasBackground' : 'shell'} style={shellStyle}>
            <div className="backgroundLayer" aria-hidden="true" style={backgroundStyle}/>
            <div className="backgroundOverlay" aria-hidden="true"/>
            <aside
                className={sidebarFocused ? 'sidebar expanded' : 'sidebar'}
                onMouseEnter={() => setSidebarFocused(true)}
                onMouseLeave={(event) => {
                    if (event.currentTarget.contains(document.activeElement)) {
                        (document.activeElement as HTMLElement | null)?.blur();
                    }
                    setSidebarFocused(false);
                }}
                onFocus={() => setSidebarFocused(true)}
                onBlur={(event) => {
                    if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setSidebarFocused(false);
                }}
            >
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
                            <button className={tab === item.id ? 'active' : ''} key={item.id} onClick={(event) => {
                                setTab(item.id);
                                event.currentTarget.blur();
                                setSidebarFocused(false);
                            }}>
                                <Icon size={18}/>
                                <span>{t(item.labelKey)}</span>
                            </button>
                        );
                    })}
                </nav>
                <div className="sidebarFooter">
                    <StatusPill ok={snapshot.running} label={snapshot.running ? t('coreRunning') : t('coreStopped')}/>
                    <StatusPill ok={snapshot.apiReachable} label={snapshot.apiReachable ? t('apiConnected') : t('apiDisconnected')}/>
                    <span className="appVersion">{snapshot.version}</span>
                </div>
            </aside>

            <section className="workspace">
                <header className="topbar">
                    <div className="topbarTitle">
                        <h1>{t(tabs.find((item) => item.id === tab)?.labelKey || 'dashboard')}</h1>
                        <p>{snapshot.activeProfile || 'Direct'}</p>
                    </div>
                    <div className="actions">
                        <button className="iconButton" title={t('refresh')} disabled={busy} onClick={() => run(async () => refreshPageData(tab))}>
                            <RefreshCcw size={18}/>
                        </button>
                        {snapshot.running ? (
                            <button className="danger" disabled={busy} onClick={() => run(StopCore, t('coreStopped'))}>
                                <CircleStop size={17}/>{t('stopped')}
                            </button>
                        ) : (
                            <button className="primary" disabled={busy} onClick={() => run(StartCore, t('coreStarted'))}>
                                <Play size={17}/>{t('start')}
                            </button>
                        )}
                        <div className="windowControls" aria-label="window controls">
                            <button className="chromeButton" title={t('minimize')} onClick={() => run(MinimizeWindow)}>
                                <Minus size={15}/>
                            </button>
                            <button className="chromeButton" title={t('maximize')} onClick={WindowToggleMaximise}>
                                <Maximize2 size={14}/>
                            </button>
                            <button className="chromeButton close" title={snapshot.settings.closeBehavior === 'exit' ? t('exit') : t('hideToTray')} onClick={() => run(CloseWindow)}>
                                <X size={15}/>
                            </button>
                        </div>
                    </div>
                </header>

                {(notice || geodataVisible) && (
                    <div className="noticeStack">
                        {notice && (
                            <div className={noticeError(notice) ? 'notice error' : 'notice'}>
                                <span>{notice}</span>
                                {adminNotice && (
                                    <button className="noticeAction" onClick={() => run(RelaunchAsAdministrator)}>
                                        <Shield size={14}/>
                                        {settingsDraft.language === 'en' ? 'Restart as admin' : '管理员重启'}
                                    </button>
                                )}
                            </div>
                        )}
                        {geodataVisible && (
                            <div className={snapshot.geodata.checking ? 'notice geodataNotice' : 'notice geodataNotice error'}>
                                <div>
                                    <strong>{snapshot.geodata.file || 'Geodata'}</strong>
                                    <span>
                                        {snapshot.geodata.total > 0
                                            ? `${formatBytes(snapshot.geodata.downloaded)} / ${formatBytes(snapshot.geodata.total)}`
                                            : snapshot.geodata.message}
                                    </span>
                                </div>
                                {snapshot.geodata.total > 0 && (
                                    <div className="usageBar">
                                        <span style={{width: `${geodataProgress}%`}}/>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                )}

                {tab === 'dashboard' && (
                    <DashboardPage
                        snapshot={snapshot}
                        connections={connectionSnapshot}
                        t={t}
                        onRestart={() => run(RestartCore, t('coreRestarted'))}
                        onOpenMihomo={() => run(() => OpenURL('https://github.com/MetaCubeX/mihomo/tree/Meta'))}
                    />
                )}

                {tab === 'proxies' && (
                    <ProxiesPage
                        groups={filteredGroups}
                        query={query}
                        t={t}
                        testingGroup={testingGroup}
                        groupStatus={proxyGroupStatus}
                        onQueryChange={setQuery}
                        onSelect={(group, node) => run(() => SelectProxy(group, node))}
                        onTestGroup={(group) => testProxyGroup(group)}
                        onTestNode={(group, node) => run(() => TestProxyNode(group, node), t('delayTested'))}
                    />
                )}

                {tab === 'profiles' && (
                    <ProfilesPage
                        snapshot={snapshot}
                        providers={providers}
                        profileURL={profileURL}
                        t={t}
                        onProfileURLChange={setProfileURL}
                        dropActive={profileDropActive}
                        updatingProfiles={profileUpdateStatus}
                        updatingProviders={providerUpdateStatus}
                        onOpenGithub={() => run(() => OpenURL('https://github.com/Admirepowered/Pulse'))}
                        onActivate={(id) => run(() => SetActiveProfile(id), t('switchedProfile'))}
                        onEdit={openEditor}
                        onRename={(profile, name) => run(() => RenameProfile(profile.id, name))}
                        onUpdateProfile={updateProfileInline}
                        onDeleteProfile={(id) => run(() => DeleteProfile(id), t('profileDeleted'))}
                        onUpdateProvider={updateProviderInline}
                        onAddSubscription={() => run(async () => {
                            await AddProfileFromURL('', profileURL);
                            setProfileURL('');
                        }, t('subscriptionAdded'))}
                        onToggleSubscriptionProxy={(enabled) => applySettings({...settingsDraft, subscriptionProxy: enabled})}
                        onDropActiveChange={setProfileDropActive}
                    />
                )}

                {tab === 'rules' && (
                    <RulesPage
                        rules={rules}
                        profiles={snapshot.profiles}
                        activeProfile={snapshot.activeProfile}
                        t={t}
                        onEditCustomRules={openRuleEditor}
                    />
                )}

                {tab === 'connections' && (
                    <ConnectionsPage
                        snapshot={connectionSnapshot}
                        connections={filteredConnections}
                        query={query}
                        t={t}
                        onQueryChange={setQuery}
                        onCloseAll={() => run(CloseAllConnections, t('connectionCleared'))}
                        onClose={(id) => run(() => CloseConnection(id), t('connectionClosed'))}
                    />
                )}

                {tab === 'logs' && <LogsPage logs={logs.length ? logs : snapshot.recentLogs}/>}

                {tab === 'settings' && (
                    <SettingsPage
                        settings={settingsDraft}
                        backgrounds={backgrounds}
                        interfaces={networkInterfaces}
                        t={t}
                        onChange={(settings) => {
                            setSettingsDraft(settings);
                            setSettingsDirty(true);
                        }}
                        onApply={applySettings}
                        onCommit={(settings) => run(() => saveSettings(settings), t('settingsSaved'))}
                        onOpenDir={() => run(OpenDataDirectory)}
                        onChooseBackground={chooseBackground}
                        onClearBackground={clearBackground}
                        onSelectBackground={(id) => applySettings({...settingsDraft, backgroundPath: id})}
                        onDeleteBackground={(id) => deleteBackground(id)}
                        onCheckUpdates={() => promptUpdate(true)}
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
                        <YamlEditor value={editorContent} onChange={setEditorContent}/>
                        <div className="modalActions">
                            <button onClick={() => setEditorProfile(null)}>{t('cancel')}</button>
                            <button className="primary" onClick={() => run(async () => {
                                await SaveProfileContent(editorProfile.id, editorContent);
                                setEditorProfile(null);
                            }, t('profileSaved'))}>
                                <Save size={17}/>{t('save')}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {ruleEditorProfile && (
                <div className="modalBackdrop">
                    <div className="modal compactModal">
                        <div className="panelHead">
                            <div>
                                <h2>{t('customRules')}</h2>
                                <span>{ruleEditorProfile.name}</span>
                            </div>
                            <button className="iconButton" onClick={() => setRuleEditorProfile(null)}>
                                <X size={18}/>
                            </button>
                        </div>
                        <p className="hintText">{t('customRulesHint')}</p>
                        <CustomRulesEditor rules={ruleEditorRules} policies={ruleEditorPolicies} t={t} onChange={setRuleEditorRules}/>
                        <div className="modalActions">
                            <button onClick={() => setRuleEditorProfile(null)}>{t('cancel')}</button>
                            <button className="primary" onClick={() => run(async () => {
                                await SaveProfileCustomRules(ruleEditorProfile.id, ruleEditorRules);
                                setRuleEditorProfile(null);
                                if (tab === 'rules') setRules(await FetchRules() as RuleRow[]);
                            }, t('profileSaved'))}>
                                <Save size={17}/>{t('save')}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </main>
    );
}

export default App;
