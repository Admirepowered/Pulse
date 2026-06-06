import {type CSSProperties, useCallback, useEffect, useMemo, useState} from 'react';
import {
    Activity,
    Bug,
    Check,
    CircleStop,
    Cloud,
    FolderOpen,
    Gauge,
    GitBranch,
    Globe2,
    Image as ImageIcon,
    Link2,
    ListChecks,
    Maximize2,
    Minus,
    Network,
    Play,
    PlugZap,
    RefreshCcw,
    RotateCcw,
    Save,
    Search,
    Settings as SettingsIcon,
    Shield,
    SquarePen,
    Trash2,
    Upload,
    Wifi,
    X,
} from 'lucide-react';
import './App.css';
import {
    AddProfileFromURL,
    CloseAllConnections,
    CloseConnection,
    DeleteProfile,
    FetchConnections,
    FetchProviders,
    FetchProxyGroups,
    FetchRules,
    GetLogs,
    GetSnapshot,
    ImportProfile,
    OpenDataDirectory,
    OpenURL,
    ReadProfileContent,
    ReadBackgroundImageDataURL,
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
} from '../wailsjs/go/main/App';
import {main as Models} from '../wailsjs/go/models';
import {Quit, WindowMinimise, WindowToggleMaximise} from '../wailsjs/runtime/runtime';

type TabId = 'dashboard' | 'proxies' | 'profiles' | 'rules' | 'connections' | 'logs' | 'settings';

type WebDAVSettings = {
    enabled: boolean;
    url: string;
    username: string;
    password: string;
};

type Settings = {
    corePath: string;
    apiBase: string;
    secret: string;
    mixedPort: number;
    allowLan: boolean;
    mode: string;
    tunEnabled: boolean;
    systemProxy: boolean;
    theme: string;
    autoStart: boolean;
    backgroundPath: string;
    backgroundBlur: number;
    webdav: WebDAVSettings;
};

type Profile = {
    id: string;
    name: string;
    type: string;
    source: string;
    path: string;
    updatedAt: number;
    enabled: boolean;
};

type LogLine = {
    time: number;
    level: string;
    message: string;
};

type RuntimeState = {
    running: boolean;
    apiReachable: boolean;
    coreFound: boolean;
    startedAt: number;
    dataDir: string;
    activeProfile: string;
    profiles: Profile[];
    settings: Settings;
    traffic: { up: number; down: number };
    recentLogs: LogLine[];
};

type ProxyNode = {
    name: string;
    type: string;
    delay: number;
    alive: boolean;
};

type ProxyGroup = {
    name: string;
    type: string;
    now: string;
    nodes: ProxyNode[];
};

type RuleRow = {
    type: string;
    payload: string;
    proxy: string;
};

type ProviderRow = {
    name: string;
    vehicle: string;
    updatedAt: string;
    proxies: number;
};

type ConnectionRow = {
    id: string;
    network: string;
    address: string;
    rule: string;
    chains: string;
    upload: number;
    download: number;
    start: string;
};

const emptySettings: Settings = {
    corePath: 'mihomo.exe',
    apiBase: 'http://127.0.0.1:9090',
    secret: '',
    mixedPort: 7890,
    allowLan: false,
    mode: 'rule',
    tunEnabled: false,
    systemProxy: false,
    theme: 'system',
    autoStart: false,
    backgroundPath: '',
    backgroundBlur: 0,
    webdav: {enabled: false, url: '', username: '', password: ''},
};

const emptySnapshot: RuntimeState = {
    running: false,
    apiReachable: false,
    coreFound: false,
    startedAt: 0,
    dataDir: '',
    activeProfile: '',
    profiles: [],
    settings: emptySettings,
    traffic: {up: 0, down: 0},
    recentLogs: [],
};

const tabs: Array<{ id: TabId; label: string; icon: typeof Gauge }> = [
    {id: 'dashboard', label: '总览', icon: Gauge},
    {id: 'proxies', label: '代理', icon: GitBranch},
    {id: 'profiles', label: '配置', icon: Cloud},
    {id: 'rules', label: '规则', icon: ListChecks},
    {id: 'connections', label: '连接', icon: Network},
    {id: 'logs', label: '日志', icon: Bug},
    {id: 'settings', label: '设置', icon: SettingsIcon},
];

function App() {
    const [tab, setTab] = useState<TabId>('dashboard');
    const [snapshot, setSnapshot] = useState<RuntimeState>(emptySnapshot);
    const [groups, setGroups] = useState<ProxyGroup[]>([]);
    const [rules, setRules] = useState<RuleRow[]>([]);
    const [providers, setProviders] = useState<ProviderRow[]>([]);
    const [connections, setConnections] = useState<ConnectionRow[]>([]);
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
    const [backgroundDataURL, setBackgroundDataURL] = useState('');

    const refreshSnapshot = useCallback(async () => {
        const next = await GetSnapshot() as RuntimeState;
        setSnapshot(normalizeSnapshot(next));
    }, []);

    const refreshPageData = useCallback(async (activeTab: TabId) => {
        if (activeTab === 'proxies') {
            setGroups(await FetchProxyGroups() as ProxyGroup[]);
        }
        if (activeTab === 'rules') {
            setRules(await FetchRules() as RuleRow[]);
        }
        if (activeTab === 'profiles') {
            setProviders(await FetchProviders() as ProviderRow[]);
        }
        if (activeTab === 'connections') {
            setConnections(await FetchConnections() as ConnectionRow[]);
        }
        if (activeTab === 'logs') {
            setLogs(await GetLogs() as LogLine[]);
        }
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

    useEffect(() => {
        refreshSnapshot().catch((error) => setNotice(String(error)));
    }, [refreshSnapshot]);

    useEffect(() => {
        setSettingsDraft(snapshot.settings);
    }, [snapshot.settings]);

    useEffect(() => {
        const path = snapshot.settings.backgroundPath;
        if (!path) {
            setBackgroundDataURL('');
            return;
        }
        ReadBackgroundImageDataURL(path)
            .then((value) => setBackgroundDataURL(value as string))
            .catch((error) => setNotice(error instanceof Error ? error.message : String(error)));
    }, [snapshot.settings.backgroundPath]);

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
        if (!value) return connections;
        return connections.filter((item) => `${item.address} ${item.rule} ${item.chains}`.toLowerCase().includes(value));
    }, [connections, query]);

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
            setSettingsDraft((current) => ({...current, backgroundPath: path}));
            setBackgroundDataURL(dataURL);
        } catch (error) {
            setNotice(error instanceof Error ? error.message : String(error));
        } finally {
            setBusy(false);
        }
    };

    const clearBackground = () => {
        setSettingsDraft((current) => ({...current, backgroundPath: ''}));
        setBackgroundDataURL('');
    };

    const shellStyle = {
        '--background-image': backgroundDataURL ? `url("${backgroundDataURL}")` : 'none',
        '--background-blur': `${Math.max(0, Math.min(40, settingsDraft.backgroundBlur || 0))}px`,
    } as CSSProperties;

    return (
        <main className={backgroundDataURL ? 'shell hasBackground' : 'shell'} style={shellStyle}>
            <aside className="sidebar">
                <div className="brand">
                    <Shield size={28}/>
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
                    <div>
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
                            <button className="chromeButton" title="最小化" onClick={WindowMinimise}>
                                <Minus size={15}/>
                            </button>
                            <button className="chromeButton" title="最大化" onClick={WindowToggleMaximise}>
                                <Maximize2 size={14}/>
                            </button>
                            <button className="chromeButton close" title="关闭" onClick={Quit}>
                                <X size={15}/>
                            </button>
                        </div>
                    </div>
                </header>

                {notice && (
                    <div className={notice.includes('error') || notice.includes('not') || notice.includes('empty') ? 'notice error' : 'notice'}>
                        {notice}
                    </div>
                )}

                {tab === 'dashboard' && (
                    <Dashboard snapshot={snapshot} onRestart={() => run(RestartCore, '核心已重启')} onOpenDir={() => run(OpenDataDirectory)}/>
                )}

                {tab === 'proxies' && (
                    <section className="stack proxyPage">
                        <SearchBox value={query} onChange={setQuery} placeholder="搜索策略组、节点、类型"/>
                        {filteredGroups.map((group) => (
                            <details className="panel proxyGroup" key={group.name}>
                                <summary className="proxyGroupHead">
                                    <span className="summaryChevron" aria-hidden="true"/>
                                    <div className="proxyGroupTitle">
                                        <h2>{group.name}</h2>
                                        <span>{group.type} · {group.now || '未选择'}</span>
                                    </div>
                                    <StatusPill ok={Boolean(group.now)} label={`${group.nodes.length} 节点`}/>
                                </summary>
                                <div className="nodeGrid">
                                    {group.nodes.map((node) => (
                                        <button
                                            className={node.name === group.now ? 'node selected' : 'node'}
                                            key={`${group.name}-${node.name}`}
                                            onClick={() => run(() => SelectProxy(group.name, node.name), `${group.name} -> ${node.name}`)}
                                        >
                                            <span>{node.name}</span>
                                            <small>{node.type || 'proxy'} · {node.delay >= 0 ? `${node.delay}ms` : '待测'}</small>
                                            {node.name === group.now && <Check size={16}/>}
                                        </button>
                                    ))}
                                </div>
                            </details>
                        ))}
                    </section>
                )}

                {tab === 'profiles' && (
                    <section className="split">
                        <div className="stack">
                            <article className="panel">
                                <div className="panelHead">
                                    <h2>Profiles</h2>
                                    <button className="ghost" onClick={() => run(() => OpenURL('https://github.com/Admirepowered/Pulse'))}>
                                        <Link2 size={16}/>GitHub
                                    </button>
                                </div>
                                <div className="profileList">
                                    {snapshot.profiles.map((profile) => (
                                        <div className="profileRow" key={profile.id}>
                                            <div>
                                                <strong>{profile.name}</strong>
                                                <span>{profile.type} · {formatTime(profile.updatedAt)}</span>
                                            </div>
                                            <div className="rowActions">
                                                <button title="启用" onClick={() => run(() => SetActiveProfile(profile.id), '已切换 Profile')}>
                                                    <Check size={16}/>
                                                </button>
                                                <button title="编辑" onClick={() => openEditor(profile)}>
                                                    <SquarePen size={16}/>
                                                </button>
                                                <button title="更新" onClick={() => run(() => UpdateProfile(profile.id), 'Profile 已更新')}>
                                                    <RefreshCcw size={16}/>
                                                </button>
                                                <button title="删除" onClick={() => run(() => DeleteProfile(profile.id), 'Profile 已删除')}>
                                                    <Trash2 size={16}/>
                                                </button>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </article>

                            <article className="panel">
                                <div className="panelHead"><h2>Proxy Providers</h2></div>
                                <div className="table">
                                    {providers.map((provider) => (
                                        <div className="tableRow" key={provider.name}>
                                            <span>{provider.name}</span>
                                            <span>{provider.vehicle || 'provider'}</span>
                                            <span>{provider.proxies} 节点</span>
                                            <button onClick={() => run(() => UpdateProvider(provider.name), 'Provider 已更新')}>
                                                <RefreshCcw size={15}/>更新
                                            </button>
                                        </div>
                                    ))}
                                </div>
                            </article>
                        </div>

                        <div className="stack">
                            <article className="panel">
                                <div className="panelHead"><h2>订阅</h2></div>
                                <Field label="名称（可选）" value={profileName} onChange={setProfileName} placeholder="留空时自动从远程订阅推断"/>
                                <Field label="URL" value={profileURL} onChange={setProfileURL} placeholder="https://example.com/profile.yaml"/>
                                <button className="primary wide" onClick={() => run(async () => {
                                    await AddProfileFromURL(profileName, profileURL);
                                    setProfileName('');
                                    setProfileURL('');
                                }, '订阅已添加')}>
                                    <Cloud size={17}/>添加订阅
                                </button>
                            </article>

                            <article className="panel">
                                <div className="panelHead"><h2>本地 YAML</h2></div>
                                <Field label="名称" value={importName} onChange={setImportName}/>
                                <textarea value={importContent} onChange={(event) => setImportContent(event.target.value)} spellCheck={false}/>
                                <button className="wide" onClick={() => run(async () => {
                                    await ImportProfile(importName, importContent);
                                    setImportName('');
                                    setImportContent('');
                                }, 'Profile 已导入')}>
                                    <Upload size={17}/>导入
                                </button>
                            </article>
                        </div>
                    </section>
                )}

                {tab === 'rules' && (
                    <article className="panel">
                        <div className="panelHead">
                            <h2>Rules</h2>
                            <StatusPill ok label={`${rules.length} 条`}/>
                        </div>
                        <div className="ruleList">
                            {rules.map((rule, index) => (
                                <div className="ruleRow" key={`${rule.type}-${rule.payload}-${index}`}>
                                    <span>{rule.type}</span>
                                    <strong>{rule.payload || 'MATCH'}</strong>
                                    <em>{rule.proxy}</em>
                                </div>
                            ))}
                        </div>
                    </article>
                )}

                {tab === 'connections' && (
                    <section className="stack">
                        <div className="toolbar">
                            <SearchBox value={query} onChange={setQuery} placeholder="搜索域名、规则、链路"/>
                            <button className="danger" onClick={() => run(CloseAllConnections, '连接已清空')}>
                                <X size={16}/>全部断开
                            </button>
                        </div>
                        <article className="panel">
                            <div className="connectionList">
                                {filteredConnections.map((item) => (
                                    <div className="connectionRow" key={item.id}>
                                        <div>
                                            <strong>{item.address || item.id}</strong>
                                            <span>{item.network} · {item.rule} · {item.chains}</span>
                                        </div>
                                        <small>{formatBytes(item.upload)} / {formatBytes(item.download)}</small>
                                        <button onClick={() => run(() => CloseConnection(item.id), '连接已断开')}>
                                            <X size={16}/>
                                        </button>
                                    </div>
                                ))}
                            </div>
                        </article>
                    </section>
                )}

                {tab === 'logs' && (
                    <article className="panel logs">
                        {(logs.length ? logs : snapshot.recentLogs).slice().reverse().map((line, index) => (
                            <div className={`logLine ${line.level}`} key={`${line.time}-${index}`}>
                                <span>{formatClock(line.time)}</span>
                                <strong>{line.level}</strong>
                                <p>{line.message}</p>
                            </div>
                        ))}
                    </article>
                )}

                {tab === 'settings' && (
                    <SettingsPanel
                        settings={settingsDraft}
                        onChange={setSettingsDraft}
                        onSave={() => run(() => SaveSettings(new Models.Settings(settingsDraft)), '设置已保存')}
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

function Dashboard({snapshot, onRestart, onOpenDir}: { snapshot: RuntimeState; onRestart: () => void; onOpenDir: () => void }) {
    const uptime = snapshot.startedAt ? Math.max(0, Math.floor(Date.now() / 1000 - snapshot.startedAt)) : 0;
    return (
        <section className="stack">
            <div className="metricGrid">
                <Metric icon={Activity} label="上行" value={formatBytes(snapshot.traffic.up)}/>
                <Metric icon={Wifi} label="下行" value={formatBytes(snapshot.traffic.down)}/>
                <Metric icon={PlugZap} label="运行" value={snapshot.running ? formatDuration(uptime) : '停止'}/>
                <Metric icon={Globe2} label="模式" value={snapshot.settings.mode.toUpperCase()}/>
            </div>
            <article className="panel">
                <div className="panelHead">
                    <div>
                        <h2>Core</h2>
                        <span>{snapshot.settings.corePath}</span>
                    </div>
                    <StatusPill ok={snapshot.coreFound} label={snapshot.coreFound ? '已找到' : '未找到'}/>
                </div>
                <div className="quickGrid">
                    <button onClick={onRestart}><RotateCcw size={17}/>重启核心</button>
                    <button onClick={onOpenDir}><FolderOpen size={17}/>数据目录</button>
                    <button onClick={() => OpenURL('https://github.com/MetaCubeX/mihomo/tree/Meta')}><GitBranch size={17}/>mihomo Meta</button>
                </div>
            </article>
            <article className="panel">
                <div className="panelHead"><h2>最近日志</h2></div>
                <div className="compactLogs">
                    {snapshot.recentLogs.slice(-8).reverse().map((line, index) => (
                        <div key={`${line.time}-${index}`}>{line.message}</div>
                    ))}
                </div>
            </article>
        </section>
    );
}

function SettingsPanel({settings, onChange, onSave, onOpenDir, onChooseBackground, onClearBackground}: {
    settings: Settings;
    onChange: (settings: Settings) => void;
    onSave: () => void;
    onOpenDir: () => void;
    onChooseBackground: () => void;
    onClearBackground: () => void;
}) {
    const set = <K extends keyof Settings>(key: K, value: Settings[K]) => onChange({...settings, [key]: value});
    const setWebDAV = <K extends keyof WebDAVSettings>(key: K, value: WebDAVSettings[K]) =>
        onChange({...settings, webdav: {...settings.webdav, [key]: value}});

    return (
        <section className="split">
            <article className="panel formPanel">
                <div className="panelHead"><h2>Core</h2></div>
                <Field label="mihomo 路径" value={settings.corePath} onChange={(value) => set('corePath', value)}/>
                <Field label="API 地址" value={settings.apiBase} onChange={(value) => set('apiBase', value)}/>
                <Field label="Secret" value={settings.secret} onChange={(value) => set('secret', value)}/>
                <Field label="Mixed Port" type="number" value={String(settings.mixedPort)} onChange={(value) => set('mixedPort', Number(value) || 7890)}/>
                <div className="segmented">
                    {['rule', 'global', 'direct'].map((mode) => (
                        <button className={settings.mode === mode ? 'active' : ''} key={mode} onClick={() => set('mode', mode)}>
                            {mode}
                        </button>
                    ))}
                </div>
                <Toggle label="Allow LAN" checked={settings.allowLan} onChange={(value) => set('allowLan', value)}/>
                <Toggle label="TUN" checked={settings.tunEnabled} onChange={(value) => set('tunEnabled', value)}/>
                <Toggle label="系统代理" checked={settings.systemProxy} onChange={(value) => set('systemProxy', value)}/>
                <Toggle label="开机启动" checked={settings.autoStart} onChange={(value) => set('autoStart', value)}/>
            </article>

            <div className="stack">
                <article className="panel formPanel">
                    <div className="panelHead"><h2>外观</h2></div>
                    <div className="backgroundPicker">
                        <div className="pathPreview" title={settings.backgroundPath || '未选择背景图片'}>
                            <ImageIcon size={17}/>
                            <span>{settings.backgroundPath || '未选择背景图片'}</span>
                        </div>
                        <div className="modalActions inline">
                            <button onClick={onChooseBackground}><ImageIcon size={17}/>选择图片</button>
                            <button disabled={!settings.backgroundPath} onClick={onClearBackground}><X size={17}/>清除</button>
                        </div>
                    </div>
                    <label className="rangeField">
                        <span>虚化程度 <strong>{settings.backgroundBlur || 0}px</strong></span>
                        <input
                            type="range"
                            min="0"
                            max="40"
                            step="1"
                            value={settings.backgroundBlur || 0}
                            onChange={(event) => set('backgroundBlur', Number(event.target.value))}
                        />
                    </label>
                </article>

                <article className="panel formPanel">
                    <div className="panelHead"><h2>同步</h2></div>
                    <Toggle label="WebDAV" checked={settings.webdav.enabled} onChange={(value) => setWebDAV('enabled', value)}/>
                    <Field label="URL" value={settings.webdav.url} onChange={(value) => setWebDAV('url', value)}/>
                    <Field label="用户名" value={settings.webdav.username} onChange={(value) => setWebDAV('username', value)}/>
                    <Field label="密码" value={settings.webdav.password} onChange={(value) => setWebDAV('password', value)}/>
                    <div className="modalActions inline">
                        <button onClick={onOpenDir}><FolderOpen size={17}/>数据目录</button>
                        <button className="primary" onClick={onSave}><Save size={17}/>保存设置</button>
                    </div>
                </article>
            </div>
        </section>
    );
}

function Metric({icon: Icon, label, value}: { icon: typeof Gauge; label: string; value: string }) {
    return (
        <article className="metric">
            <Icon size={20}/>
            <span>{label}</span>
            <strong>{value}</strong>
        </article>
    );
}

function Field({label, value, onChange, type = 'text', placeholder}: {
    label: string;
    value: string;
    onChange: (value: string) => void;
    type?: string;
    placeholder?: string;
}) {
    return (
        <label className="field">
            <span>{label}</span>
            <input type={type} value={value} placeholder={placeholder} onChange={(event) => onChange(event.target.value)}/>
        </label>
    );
}

function Toggle({label, checked, onChange}: { label: string; checked: boolean; onChange: (value: boolean) => void }) {
    return (
        <label className="toggle">
            <span>{label}</span>
            <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)}/>
        </label>
    );
}

function SearchBox({value, onChange, placeholder}: { value: string; onChange: (value: string) => void; placeholder: string }) {
    return (
        <label className="search">
            <Search size={17}/>
            <input value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder}/>
        </label>
    );
}

function StatusPill({ok, label}: { ok: boolean; label: string }) {
    return <span className={ok ? 'pill ok' : 'pill'}>{label}</span>;
}

function normalizeSnapshot(snapshot: RuntimeState): RuntimeState {
    return {
        ...emptySnapshot,
        ...snapshot,
        settings: {
            ...emptySettings,
            ...snapshot.settings,
            webdav: {...emptySettings.webdav, ...(snapshot.settings?.webdav || {})},
        },
        traffic: snapshot.traffic || {up: 0, down: 0},
        profiles: snapshot.profiles || [],
        recentLogs: snapshot.recentLogs || [],
    };
}

function formatBytes(bytes: number) {
    if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let value = bytes;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
        value /= 1024;
        unit += 1;
    }
    return `${value.toFixed(value >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function formatDuration(seconds: number) {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    if (h) return `${h}h ${m}m`;
    if (m) return `${m}m ${s}s`;
    return `${s}s`;
}

function formatTime(timestamp: number) {
    if (!timestamp) return '未更新';
    return new Date(timestamp * 1000).toLocaleString();
}

function formatClock(timestamp: number) {
    if (!timestamp) return '--:--:--';
    return new Date(timestamp * 1000).toLocaleTimeString();
}

export default App;
