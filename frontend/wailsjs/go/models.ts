export namespace main {
	
	export class ConnectionRow {
	    id: string;
	    network: string;
	    address: string;
	    rule: string;
	    chains: string;
	    upload: number;
	    download: number;
	    start: string;
	
	    static createFrom(source: any = {}) {
	        return new ConnectionRow(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.network = source["network"];
	        this.address = source["address"];
	        this.rule = source["rule"];
	        this.chains = source["chains"];
	        this.upload = source["upload"];
	        this.download = source["download"];
	        this.start = source["start"];
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
	export class Profile {
	    id: string;
	    name: string;
	    type: string;
	    source: string;
	    path: string;
	    updatedAt: number;
	    enabled: boolean;
	
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
	    tunEnabled: boolean;
	    systemProxy: boolean;
	    theme: string;
	    autoStart: boolean;
	    autoStartCore: boolean;
	    backgroundPath: string;
	    backgroundBlur: number;
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
	        this.tunEnabled = source["tunEnabled"];
	        this.systemProxy = source["systemProxy"];
	        this.theme = source["theme"];
	        this.autoStart = source["autoStart"];
	        this.autoStartCore = source["autoStartCore"];
	        this.backgroundPath = source["backgroundPath"];
	        this.backgroundBlur = source["backgroundBlur"];
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
	    startedAt: number;
	    dataDir: string;
	    activeProfile: string;
	    profiles: Profile[];
	    settings: Settings;
	    traffic: TrafficSnapshot;
	    recentLogs: LogLine[];
	
	    static createFrom(source: any = {}) {
	        return new RuntimeState(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.running = source["running"];
	        this.apiReachable = source["apiReachable"];
	        this.coreFound = source["coreFound"];
	        this.startedAt = source["startedAt"];
	        this.dataDir = source["dataDir"];
	        this.activeProfile = source["activeProfile"];
	        this.profiles = this.convertValues(source["profiles"], Profile);
	        this.settings = this.convertValues(source["settings"], Settings);
	        this.traffic = this.convertValues(source["traffic"], TrafficSnapshot);
	        this.recentLogs = this.convertValues(source["recentLogs"], LogLine);
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

