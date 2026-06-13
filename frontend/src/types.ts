export type TabId = 'dashboard' | 'proxies' | 'profiles' | 'rules' | 'connections' | 'logs' | 'tun' | 'settings';

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
    tunInterface: string;
    tunStack: string;
    tunAutoRoute: boolean;
    tunAutoRedirect: boolean;
    tunAutoDetectInterface: boolean;
    tunDNSHijack: string[];
    tunDevice: string;
    tunMTU: number;
    tunStrictRoute: boolean;
    tunGSO: boolean;
    tunGSOMaxSize: number;
    tunInet6Address: string;
    tunUDPTimeout: number;
    tunIPRoute2TableIndex: number;
    tunIPRoute2RuleIndex: number;
    tunEndpointIndependentNAT: boolean;
    tunRouteAddressSet: string[];
    tunRouteExcludeAddressSet: string[];
    tunRouteAddress: string[];
    tunRouteExcludeAddress: string[];
    tunIncludeInterface: string[];
    tunExcludeInterface: string[];
    tunIncludeUID: number[];
    tunIncludeUIDRange: string[];
    tunExcludeUID: number[];
    tunExcludeUIDRange: string[];
    tunIncludeAndroidUser: number[];
    tunIncludePackage: string[];
    tunExcludePackage: string[];
    tunInet4RouteAddress: string[];
    tunInet6RouteAddress: string[];
    tunInet4RouteExcludeAddress: string[];
    tunInet6RouteExcludeAddress: string[];
    systemProxy: boolean;
    delayTestUrl: string;
    language: string;
    theme: string;
    autoStart: boolean;
    autoStartService: boolean;
    autoStartServiceDaemon: boolean;
    autoStartCore: boolean;
    disableUpdateCheck: boolean;
    closeBehavior: string;
    subscriptionProxy: boolean;
    backgroundPath: string;
    backgroundBlur: number;
    backgroundOpacity: number;
    webdav: WebDAVSettings;
};

export type BackgroundImage = {
    id: string;
    name: string;
};

export type NetworkInterface = {
    name: string;
    displayName: string;
    addresses: string[];
};

export type UpdateInfo = {
    currentVersion: string;
    latestVersion: string;
    available: boolean;
    url: string;
    assetName: string;
    message: string;
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

export type CustomRule = {
    id: string;
    type: string;
    payload: string;
    proxy: string;
    noResolve: boolean;
};

export type RuntimeState = {
    running: boolean;
    apiReachable: boolean;
    coreFound: boolean;
    version: string;
    buildNumber: string;
    serviceBuildNumber: string;
    serviceCurrentNumber: string;
    serviceUpdateAvailable: boolean;
    platform: string;
    appEmbeddedCore: boolean;
    serviceEmbeddedCore: boolean;
    coreModeImplementation: string;
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
    uploadSpeed: number;
    downloadSpeed: number;
    start: string;
    closedAt: number;
};

export type ConnectionSnapshot = {
    uploadTotal: number;
    downloadTotal: number;
    memory: number;
    uploadSpeed: number;
    downloadSpeed: number;
    connections: ConnectionRow[];
    closed: ConnectionRow[];
};

export type ProxyNodeConfig = {
    name: string;
    type: string;
    server: string;
    port: number;
    password?: string;
    cipher?: string;
    uuid?: string;
    alterId?: number;
    username?: string;
    network?: string;
    wsHost?: string;
    wsPath?: string;
    sni?: string;
    skipVerify?: boolean;
    udp?: boolean;
};

export type RelayChainConfig = {
    name: string;
    node1: string;
    node2: string;
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
    logLevel: 'silent',
    tunEnabled: false,
    tunInterface: '',
    tunStack: 'mixed',
    tunAutoRoute: true,
    tunAutoRedirect: true,
    tunAutoDetectInterface: true,
    tunDNSHijack: ['any:53', 'tcp://any:53'],
    tunDevice: '',
    tunMTU: 0,
    tunStrictRoute: false,
    tunGSO: false,
    tunGSOMaxSize: 0,
    tunInet6Address: '',
    tunUDPTimeout: 0,
    tunIPRoute2TableIndex: 0,
    tunIPRoute2RuleIndex: 0,
    tunEndpointIndependentNAT: false,
    tunRouteAddressSet: [],
    tunRouteExcludeAddressSet: [],
    tunRouteAddress: [],
    tunRouteExcludeAddress: [],
    tunIncludeInterface: [],
    tunExcludeInterface: [],
    tunIncludeUID: [],
    tunIncludeUIDRange: [],
    tunExcludeUID: [],
    tunExcludeUIDRange: [],
    tunIncludeAndroidUser: [],
    tunIncludePackage: [],
    tunExcludePackage: [],
    tunInet4RouteAddress: [],
    tunInet6RouteAddress: [],
    tunInet4RouteExcludeAddress: [],
    tunInet6RouteExcludeAddress: [],
    systemProxy: false,
    delayTestUrl: 'https://www.gstatic.com/generate_204',
    language: 'zh',
    theme: 'system',
    autoStart: false,
    autoStartService: false,
    autoStartServiceDaemon: false,
    autoStartCore: true,
    disableUpdateCheck: false,
    closeBehavior: 'minimize',
    subscriptionProxy: false,
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
    closed: [],
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
    serviceBuildNumber: '',
    serviceCurrentNumber: '',
    serviceUpdateAvailable: false,
    platform: '',
    appEmbeddedCore: false,
    serviceEmbeddedCore: false,
    coreModeImplementation: 'external',
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
    const next = {
        ...emptySettings,
        ...(settings || {}),
        logLevel: settings?.logLevel || 'silent',
        language: settings?.language || 'zh',
        webdav: {...emptySettings.webdav, ...(settings?.webdav || {})},
    };
    const autoStartService = next.autoStart ? false : next.autoStartService;
    return {
        ...next,
        autoStartService,
        autoStartServiceDaemon: autoStartService ? next.autoStartServiceDaemon : false,
        tunStack: next.tunStack || 'mixed',
        tunDNSHijack: stringList(next.tunDNSHijack, emptySettings.tunDNSHijack),
        tunRouteAddressSet: stringList(next.tunRouteAddressSet),
        tunRouteExcludeAddressSet: stringList(next.tunRouteExcludeAddressSet),
        tunRouteAddress: stringList(next.tunRouteAddress),
        tunRouteExcludeAddress: stringList(next.tunRouteExcludeAddress),
        tunIncludeInterface: stringList(next.tunIncludeInterface),
        tunExcludeInterface: stringList(next.tunExcludeInterface),
        tunIncludeUID: numberList(next.tunIncludeUID),
        tunIncludeUIDRange: stringList(next.tunIncludeUIDRange),
        tunExcludeUID: numberList(next.tunExcludeUID),
        tunExcludeUIDRange: stringList(next.tunExcludeUIDRange),
        tunIncludeAndroidUser: numberList(next.tunIncludeAndroidUser),
        tunIncludePackage: stringList(next.tunIncludePackage),
        tunExcludePackage: stringList(next.tunExcludePackage),
        tunInet4RouteAddress: stringList(next.tunInet4RouteAddress),
        tunInet6RouteAddress: stringList(next.tunInet6RouteAddress),
        tunInet4RouteExcludeAddress: stringList(next.tunInet4RouteExcludeAddress),
        tunInet6RouteExcludeAddress: stringList(next.tunInet6RouteExcludeAddress),
    };
}

function stringList(value: unknown, fallback: string[] = []) {
    return Array.isArray(value) ? value.map(String).filter(Boolean) : fallback;
}

function numberList(value: unknown) {
    return Array.isArray(value) ? value.map(Number).filter(Number.isInteger) : [];
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
