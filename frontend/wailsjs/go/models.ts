export namespace pulse {

	export class BackgroundImage {
	    id: string;
	    name: string;

	    static createFrom(source: any = {}) {
	        return new BackgroundImage(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	    }
	}
	export class UpdateInfo {
	    currentVersion: string;
	    latestVersion: string;
	    available: boolean;
	    url: string;
	    assetName: string;
	    message: string;

	    static createFrom(source: any = {}) {
	        return new UpdateInfo(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.currentVersion = source["currentVersion"];
	        this.latestVersion = source["latestVersion"];
	        this.available = source["available"];
	        this.url = source["url"];
	        this.assetName = source["assetName"];
	        this.message = source["message"];
	    }
	}
	export class ConnectionRow {
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

	    static createFrom(source: any = {}) {
	        return new ConnectionRow(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.network = source["network"];
	        this.address = source["address"];
	        this.destinationIp = source["destinationIp"];
	        this.source = source["source"];
	        this.process = source["process"];
	        this.rule = source["rule"];
	        this.chains = source["chains"];
	        this.upload = source["upload"];
	        this.download = source["download"];
	        this.uploadSpeed = source["uploadSpeed"];
	        this.downloadSpeed = source["downloadSpeed"];
	        this.start = source["start"];
	        this.closedAt = source["closedAt"];
	    }
	}
	export class ConnectionSnapshot {
	    uploadTotal: number;
	    downloadTotal: number;
	    memory: number;
	    uploadSpeed: number;
	    downloadSpeed: number;
	    connections: ConnectionRow[];
	    closed: ConnectionRow[];

	    static createFrom(source: any = {}) {
	        return new ConnectionSnapshot(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.uploadTotal = source["uploadTotal"];
	        this.downloadTotal = source["downloadTotal"];
	        this.memory = source["memory"];
	        this.uploadSpeed = source["uploadSpeed"];
	        this.downloadSpeed = source["downloadSpeed"];
	        this.connections = this.convertValues(source["connections"], ConnectionRow);
	        this.closed = this.convertValues(source["closed"], ConnectionRow);
	    }

		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class GeodataStatus {
	    checking: boolean;
	    ready: boolean;
	    file: string;
	    message: string;
	    downloaded: number;
	    total: number;
	    updatedAt: number;

	    static createFrom(source: any = {}) {
	        return new GeodataStatus(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.checking = source["checking"];
	        this.ready = source["ready"];
	        this.file = source["file"];
	        this.message = source["message"];
	        this.downloaded = source["downloaded"];
	        this.total = source["total"];
	        this.updatedAt = source["updatedAt"];
	    }
	}
	export class LogLine {
	    time: number;
	    level: string;
	    message: string;

	    static createFrom(source: any = {}) {
	        return new LogLine(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.time = source["time"];
	        this.level = source["level"];
	        this.message = source["message"];
	    }
	}
	export class SubscriptionInfo {
	    upload: number;
	    download: number;
	    total: number;
	    expire: number;
	    updateInterval: number;
	    rawUserInfo: string;
	    updatedAt: number;

	    static createFrom(source: any = {}) {
	        return new SubscriptionInfo(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.upload = source["upload"];
	        this.download = source["download"];
	        this.total = source["total"];
	        this.expire = source["expire"];
	        this.updateInterval = source["updateInterval"];
	        this.rawUserInfo = source["rawUserInfo"];
	        this.updatedAt = source["updatedAt"];
	    }
	}
	export class Profile {
	    id: string;
	    name: string;
	    type: string;
	    source: string;
	    path: string;
	    updatedAt: number;
	    enabled: boolean;
	    subscription: SubscriptionInfo;

	    static createFrom(source: any = {}) {
	        return new Profile(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.type = source["type"];
	        this.source = source["source"];
	        this.path = source["path"];
	        this.updatedAt = source["updatedAt"];
	        this.enabled = source["enabled"];
	        this.subscription = this.convertValues(source["subscription"], SubscriptionInfo);
	    }

		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class CustomRule {
	    id: string;
	    type: string;
	    payload: string;
	    proxy: string;
	    noResolve: boolean;

	    static createFrom(source: any = {}) {
	        return new CustomRule(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.type = source["type"];
	        this.payload = source["payload"];
	        this.proxy = source["proxy"];
	        this.noResolve = source["noResolve"];
	    }
	}
	export class ProviderRow {
	    name: string;
	    vehicle: string;
	    updatedAt: string;
	    proxies: number;

	    static createFrom(source: any = {}) {
	        return new ProviderRow(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.vehicle = source["vehicle"];
	        this.updatedAt = source["updatedAt"];
	        this.proxies = source["proxies"];
	    }
	}
	export class ProxyNode {
	    name: string;
	    type: string;
	    delay: number;
	    alive: boolean;

	    static createFrom(source: any = {}) {
	        return new ProxyNode(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.type = source["type"];
	        this.delay = source["delay"];
	        this.alive = source["alive"];
	    }
	}
	export class ProxyGroup {
	    name: string;
	    type: string;
	    now: string;
	    nodes: ProxyNode[];

	    static createFrom(source: any = {}) {
	        return new ProxyGroup(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.type = source["type"];
	        this.now = source["now"];
	        this.nodes = this.convertValues(source["nodes"], ProxyNode);
	    }

		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

	export class RuleRow {
	    type: string;
	    payload: string;
	    proxy: string;

	    static createFrom(source: any = {}) {
	        return new RuleRow(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.type = source["type"];
	        this.payload = source["payload"];
	        this.proxy = source["proxy"];
	    }
	}
	export class TrafficSnapshot {
	    up: number;
	    down: number;

	    static createFrom(source: any = {}) {
	        return new TrafficSnapshot(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.up = source["up"];
	        this.down = source["down"];
	    }
	}
	export class NetworkInterface {
	    name: string;
	    displayName: string;
	    addresses: string[];

	    static createFrom(source: any = {}) {
	        return new NetworkInterface(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.displayName = source["displayName"];
	        this.addresses = source["addresses"];
	    }
	}
	export class WebDAVSettings {
	    enabled: boolean;
	    url: string;
	    username: string;
	    password: string;

	    static createFrom(source: any = {}) {
	        return new WebDAVSettings(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.enabled = source["enabled"];
	        this.url = source["url"];
	        this.username = source["username"];
	        this.password = source["password"];
	    }
	}
	export class Settings {
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
	    autoStartCore: boolean;
	    closeBehavior: string;
	    subscriptionProxy: boolean;
	    backgroundPath: string;
	    backgroundBlur: number;
	    backgroundOpacity: number;
	    webdav: WebDAVSettings;

	    static createFrom(source: any = {}) {
	        return new Settings(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.corePath = source["corePath"];
	        this.coreMode = source["coreMode"];
	        this.apiBase = source["apiBase"];
	        this.secret = source["secret"];
	        this.mixedPort = source["mixedPort"];
	        this.allowLan = source["allowLan"];
	        this.mode = source["mode"];
	        this.logLevel = source["logLevel"];
	        this.tunEnabled = source["tunEnabled"];
	        this.tunInterface = source["tunInterface"];
	        this.tunStack = source["tunStack"];
	        this.tunAutoRoute = source["tunAutoRoute"];
	        this.tunAutoRedirect = source["tunAutoRedirect"];
	        this.tunAutoDetectInterface = source["tunAutoDetectInterface"];
	        this.tunDNSHijack = source["tunDNSHijack"];
	        this.tunDevice = source["tunDevice"];
	        this.tunMTU = source["tunMTU"];
	        this.tunStrictRoute = source["tunStrictRoute"];
	        this.tunGSO = source["tunGSO"];
	        this.tunGSOMaxSize = source["tunGSOMaxSize"];
	        this.tunInet6Address = source["tunInet6Address"];
	        this.tunUDPTimeout = source["tunUDPTimeout"];
	        this.tunIPRoute2TableIndex = source["tunIPRoute2TableIndex"];
	        this.tunIPRoute2RuleIndex = source["tunIPRoute2RuleIndex"];
	        this.tunEndpointIndependentNAT = source["tunEndpointIndependentNAT"];
	        this.tunRouteAddressSet = source["tunRouteAddressSet"];
	        this.tunRouteExcludeAddressSet = source["tunRouteExcludeAddressSet"];
	        this.tunRouteAddress = source["tunRouteAddress"];
	        this.tunRouteExcludeAddress = source["tunRouteExcludeAddress"];
	        this.tunIncludeInterface = source["tunIncludeInterface"];
	        this.tunExcludeInterface = source["tunExcludeInterface"];
	        this.tunIncludeUID = source["tunIncludeUID"];
	        this.tunIncludeUIDRange = source["tunIncludeUIDRange"];
	        this.tunExcludeUID = source["tunExcludeUID"];
	        this.tunExcludeUIDRange = source["tunExcludeUIDRange"];
	        this.tunIncludeAndroidUser = source["tunIncludeAndroidUser"];
	        this.tunIncludePackage = source["tunIncludePackage"];
	        this.tunExcludePackage = source["tunExcludePackage"];
	        this.tunInet4RouteAddress = source["tunInet4RouteAddress"];
	        this.tunInet6RouteAddress = source["tunInet6RouteAddress"];
	        this.tunInet4RouteExcludeAddress = source["tunInet4RouteExcludeAddress"];
	        this.tunInet6RouteExcludeAddress = source["tunInet6RouteExcludeAddress"];
	        this.systemProxy = source["systemProxy"];
	        this.delayTestUrl = source["delayTestUrl"];
	        this.language = source["language"];
	        this.theme = source["theme"];
	        this.autoStart = source["autoStart"];
	        this.autoStartService = source["autoStartService"];
	        this.autoStartCore = source["autoStartCore"];
	        this.closeBehavior = source["closeBehavior"];
	        this.subscriptionProxy = source["subscriptionProxy"];
	        this.backgroundPath = source["backgroundPath"];
	        this.backgroundBlur = source["backgroundBlur"];
	        this.backgroundOpacity = source["backgroundOpacity"];
	        this.webdav = this.convertValues(source["webdav"], WebDAVSettings);
	    }

		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class RuntimeState {
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

	    static createFrom(source: any = {}) {
	        return new RuntimeState(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.running = source["running"];
	        this.apiReachable = source["apiReachable"];
	        this.coreFound = source["coreFound"];
	        this.version = source["version"];
	        this.buildNumber = source["buildNumber"];
	        this.startedAt = source["startedAt"];
	        this.dataDir = source["dataDir"];
	        this.activeProfile = source["activeProfile"];
	        this.profiles = this.convertValues(source["profiles"], Profile);
	        this.settings = this.convertValues(source["settings"], Settings);
	        this.traffic = this.convertValues(source["traffic"], TrafficSnapshot);
	        this.recentLogs = this.convertValues(source["recentLogs"], LogLine);
	        this.geodata = this.convertValues(source["geodata"], GeodataStatus);
	    }

		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}




}
