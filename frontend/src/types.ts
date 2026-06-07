export type TabId = 'dashboard' | 'proxies' | 'profiles' | 'rules' | 'connections' | 'logs' | 'settings';

export type WebDAVSettings = {
    enabled: boolean;
    url: string;
    username: string;
    password: string;
};

export type Settings = {
    corePath: string;
    coreMode: string;
    apiBase: string;
    secret: string;
    mixedPort: number;
    allowLan: boolean;
    mode: string;
    logLevel: string;
    tunEnabled: boolean;
    systemProxy: boolean;
    language: string;
    theme: string;
    autoStart: boolean;
    autoStartCore: boolean;
    closeBehavior: string;
    backgroundPath: string;
    backgroundBlur: number;
    backgroundOpacity: number;
    webdav: WebDAVSettings;
};

export type SubscriptionInfo = {
    upload: number;
    download: number;
    total: number;
    expire: number;
    updateInterval: number;
    rawUserInfo: string;
    updatedAt: number;
};

export type Profile = {
    id: string;
    name: string;
    type: string;
    source: string;
    path: string;
    updatedAt: number;
    enabled: boolean;
    subscription: SubscriptionInfo;
};

export type RuntimeState = {
    running: boolean;
    apiReachable: boolean;
    coreFound: boolean;
    version: string;
    buildNumber: string;
    startedAt: number;
    dataDir: string;
    activeProfile: string;
    profiles: Profile[];
    settings: Settings;
    traffic: TrafficSnapshot;
    recentLogs: LogLine[];
    geodata: GeodataStatus;
};

export type GeodataStatus = {
    checking: boolean;
    ready: boolean;
    file: string;
    message: string;
    downloaded: number;
    total: number;
    updatedAt: number;
};

export type TrafficSnapshot = {
    up: number;
    down: number;
};

export type LogLine = {
    time: number;
    level: string;
    message: string;
};

export type ProxyGroup = {
    name: string;
    type: string;
    now: string;
    nodes: ProxyNode[];
};

export type ProxyNode = {
    name: string;
    type: string;
    delay: number;
    alive: boolean;
};

export type RuleRow = {
    type: string;
    payload: string;
    proxy: string;
};

export type ProviderRow = {
    name: string;
    vehicle: string;
    updatedAt: string;
    proxies: number;
};

export type ConnectionRow = {
    id: string;
    network: string;
    address: string;
    destinationIp: string;
    source: string;
    process: string;
    rule: string;
    chains: string;
    upload: number;
    download: number;
    start: string;
};

export type ConnectionSnapshot = {
    uploadTotal: number;
    downloadTotal: number;
    memory: number;
    uploadSpeed: number;
    downloadSpeed: number;
    connections: ConnectionRow[];
};

export const emptySubscriptionInfo: SubscriptionInfo = {
    upload: 0,
    download: 0,
    total: 0,
    expire: 0,
    updateInterval: 0,
    rawUserInfo: '',
    updatedAt: 0,
};

export const emptySettings: Settings = {
    corePath: 'mihomo.exe',
    coreMode: 'embedded',
    apiBase: 'http://127.0.0.1:9090',
    secret: '',
    mixedPort: 7890,
    allowLan: false,
    mode: 'rule',
    logLevel: 'info',
    tunEnabled: false,
    systemProxy: false,
    language: 'zh',
    theme: 'light',
    autoStart: false,
    autoStartCore: true,
    closeBehavior: 'minimize',
    backgroundPath: '',
    backgroundBlur: 0,
    backgroundOpacity: 62,
    webdav: {enabled: false, url: '', username: '', password: ''},
};

export const emptyConnectionSnapshot: ConnectionSnapshot = {
    uploadTotal: 0,
    downloadTotal: 0,
    memory: 0,
    uploadSpeed: 0,
    downloadSpeed: 0,
    connections: [],
};

export const emptyGeodataStatus: GeodataStatus = {
    checking: false,
    ready: false,
    file: '',
    message: '',
    downloaded: 0,
    total: 0,
    updatedAt: 0,
};

export const emptySnapshot: RuntimeState = {
    running: false,
    apiReachable: false,
    coreFound: false,
    version: 'P0',
    buildNumber: '0',
    startedAt: 0,
    dataDir: '',
    activeProfile: '',
    profiles: [],
    settings: emptySettings,
    traffic: {up: 0, down: 0},
    recentLogs: [],
    geodata: emptyGeodataStatus,
};

export function normalizeSettings(settings?: Partial<Settings>): Settings {
    return {
        ...emptySettings,
        ...(settings || {}),
        logLevel: settings?.logLevel || 'info',
        language: settings?.language || 'zh',
        webdav: {...emptySettings.webdav, ...(settings?.webdav || {})},
    };
}

export function normalizeSnapshot(snapshot: Partial<RuntimeState>): RuntimeState {
    return {
        ...emptySnapshot,
        ...snapshot,
        settings: normalizeSettings(snapshot.settings),
        traffic: snapshot.traffic || {up: 0, down: 0},
        geodata: {...emptyGeodataStatus, ...(snapshot.geodata || {})},
        profiles: (snapshot.profiles || []).map((profile) => ({
            ...profile,
            subscription: {...emptySubscriptionInfo, ...(profile.subscription || {})},
        })),
        recentLogs: snapshot.recentLogs || [],
    };
}
