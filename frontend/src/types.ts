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
    tunEnabled: boolean;
    systemProxy: boolean;
    theme: string;
    autoStart: boolean;
    autoStartCore: boolean;
    closeBehavior: string;
    backgroundPath: string;
    backgroundBlur: number;
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
    startedAt: number;
    dataDir: string;
    activeProfile: string;
    profiles: Profile[];
    settings: Settings;
    traffic: TrafficSnapshot;
    recentLogs: LogLine[];
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
    rule: string;
    chains: string;
    upload: number;
    download: number;
    start: string;
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
    tunEnabled: false,
    systemProxy: false,
    theme: 'light',
    autoStart: false,
    autoStartCore: true,
    closeBehavior: 'minimize',
    backgroundPath: '',
    backgroundBlur: 0,
    webdav: {enabled: false, url: '', username: '', password: ''},
};

export const emptySnapshot: RuntimeState = {
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

export function normalizeSettings(settings?: Partial<Settings>): Settings {
    return {
        ...emptySettings,
        ...(settings || {}),
        webdav: {...emptySettings.webdav, ...(settings?.webdav || {})},
    };
}

export function normalizeSnapshot(snapshot: RuntimeState): RuntimeState {
    return {
        ...emptySnapshot,
        ...snapshot,
        settings: normalizeSettings(snapshot.settings),
        traffic: snapshot.traffic || {up: 0, down: 0},
        profiles: (snapshot.profiles || []).map((profile) => ({
            ...profile,
            subscription: {...emptySubscriptionInfo, ...(profile.subscription || {})},
        })),
        recentLogs: snapshot.recentLogs || [],
    };
}
