import {useEffect, useMemo, useState} from 'react';
import {Toggle} from '../components/common';
import type {NetworkInterface, Settings} from '../types';

type TunPageProps = {
    settings: Settings;
    interfaces: NetworkInterface[];
    onChange: (settings: Settings) => void;
    onCommit: (settings: Settings) => void;
};

const stacks = [
    {id: 'mixed', label: 'mixed'},
    {id: 'system', label: 'system'},
    {id: 'gvisor', label: 'gvisor'},
] as const;

export function TunPage({settings, interfaces, onChange, onCommit}: TunPageProps) {
    const draft = <K extends keyof Settings>(key: K, value: Settings[K]) => onChange(normalizeTunSettings({...settings, [key]: value}));
    const commit = <K extends keyof Settings>(key: K, value: Settings[K]) => onCommit(normalizeTunSettings({...settings, [key]: value}));
    const selectedInterface = settings.tunIncludeInterface?.[0] || settings.tunInterface || '';
    const interfaceOptions = useMemo(() => interfaces.map((item) => ({
        value: item.name,
        label: `${item.displayName || item.name}${item.addresses?.length ? ` - ${item.addresses[0]}` : ''}`,
    })), [interfaces]);

    const commitInterface = (value: string) => onCommit(normalizeTunSettings({
        ...settings,
        tunInterface: value,
        tunIncludeInterface: value ? [value] : [],
        tunExcludeInterface: [],
    }));

    return (
        <section className="tunPage">
            <article className="panel formPanel tunPrimaryPanel">
                <div className="panelHead"><h2>TUN</h2></div>
                <div className="tunToggleGrid">
                    <Toggle label="启用 TUN" checked={settings.tunEnabled} onChange={(value) => commit('tunEnabled', value)}/>
                    <Toggle label="自动路由" checked={settings.tunAutoRoute} onChange={(value) => commit('tunAutoRoute', value)}/>
                    <Toggle label="自动重定向" checked={settings.tunAutoRedirect} onChange={(value) => commit('tunAutoRedirect', value)}/>
                    <Toggle label="自动检测出口" checked={settings.tunAutoDetectInterface} onChange={(value) => commit('tunAutoDetectInterface', value)}/>
                    <Toggle label="严格路由" checked={settings.tunStrictRoute} onChange={(value) => commit('tunStrictRoute', value)}/>
                    <Toggle label="端点独立 NAT" checked={settings.tunEndpointIndependentNAT} onChange={(value) => commit('tunEndpointIndependentNAT', value)}/>
                </div>
                <label className="field">
                    <span>协议栈</span>
                    <select className="selectControl wideSelect" value={settings.tunStack || 'mixed'} onChange={(event) => commit('tunStack', event.target.value)}>
                        {stacks.map((stack) => <option key={stack.id} value={stack.id}>{stack.label}</option>)}
                    </select>
                </label>
                <label className="field">
                    <span>路由接口</span>
                    <select className="selectControl wideSelect" value={selectedInterface} onChange={(event) => commitInterface(event.target.value)}>
                        <option value="">自动检测</option>
                        {interfaceOptions.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
                    </select>
                </label>
                <div className="tunFieldGrid">
                    <AutoTextField label="设备名称 (device)" value={settings.tunDevice} placeholder="utun0" onDraft={(value) => draft('tunDevice', value)} onCommit={(value) => commit('tunDevice', value)}/>
                    <AutoNumberField label="最大传输单元 (MTU)" value={settings.tunMTU} placeholder="9000" onCommit={(value) => commit('tunMTU', value)}/>
                    <AutoNumberField label="UDP 超时" value={settings.tunUDPTimeout} placeholder="300" onCommit={(value) => commit('tunUDPTimeout', value)}/>
                </div>
                <AutoTextField label="IPv6 地址 (inet6-address)" value={settings.tunInet6Address} placeholder="fdfe:dcba:9876::1/126" onDraft={(value) => draft('tunInet6Address', value)} onCommit={(value) => commit('tunInet6Address', value)}/>
                <AutoListField label="DNS 劫持" value={settings.tunDNSHijack} placeholder={'any:53\ntcp://any:53'} onDraft={(value) => draft('tunDNSHijack', value)} onCommit={(value) => commit('tunDNSHijack', value)}/>
            </article>

            <article className="panel formPanel">
                <div className="panelHead"><h2>路由</h2></div>
                <AutoListField label="自定义路由网段" value={settings.tunRouteAddress} placeholder={'0.0.0.0/1\n128.0.0.0/1\n::/1\n8000::/1'} onDraft={(value) => draft('tunRouteAddress', value)} onCommit={(value) => commit('tunRouteAddress', value)}/>
                <AutoListField label="排除路由网段" value={settings.tunRouteExcludeAddress} placeholder={'192.168.0.0/16\nfc00::/7'} onDraft={(value) => draft('tunRouteExcludeAddress', value)} onCommit={(value) => commit('tunRouteExcludeAddress', value)}/>
            </article>

            <details className="panel tunDetails">
                <summary>Linux</summary>
                <div className="formPanel">
                    <Toggle label="通用分段卸载 (GSO)" checked={settings.tunGSO} onChange={(value) => commit('tunGSO', value)}/>
                    <div className="tunFieldGrid">
                        <AutoNumberField label="GSO 最大长度" value={settings.tunGSOMaxSize} placeholder="65536" onCommit={(value) => commit('tunGSOMaxSize', value)}/>
                        <AutoNumberField label="路由表索引" value={settings.tunIPRoute2TableIndex} placeholder="2022" onCommit={(value) => commit('tunIPRoute2TableIndex', value)}/>
                        <AutoNumberField label="规则起始索引" value={settings.tunIPRoute2RuleIndex} placeholder="9000" onCommit={(value) => commit('tunIPRoute2RuleIndex', value)}/>
                    </div>
                    <AutoListField label="规则集路由" value={settings.tunRouteAddressSet} placeholder="ruleset-1" onDraft={(value) => draft('tunRouteAddressSet', value)} onCommit={(value) => commit('tunRouteAddressSet', value)}/>
                    <AutoListField label="规则集排除路由" value={settings.tunRouteExcludeAddressSet} placeholder="ruleset-2" onDraft={(value) => draft('tunRouteExcludeAddressSet', value)} onCommit={(value) => commit('tunRouteExcludeAddressSet', value)}/>
                    <AutoNumberListField label="包含 UID" value={settings.tunIncludeUID} placeholder="0" onDraft={(value) => draft('tunIncludeUID', value)} onCommit={(value) => commit('tunIncludeUID', value)}/>
                    <AutoListField label="包含 UID 范围" value={settings.tunIncludeUIDRange} placeholder="1000:9999" onDraft={(value) => draft('tunIncludeUIDRange', value)} onCommit={(value) => commit('tunIncludeUIDRange', value)}/>
                    <AutoNumberListField label="排除 UID" value={settings.tunExcludeUID} placeholder="1000" onDraft={(value) => draft('tunExcludeUID', value)} onCommit={(value) => commit('tunExcludeUID', value)}/>
                    <AutoListField label="排除 UID 范围" value={settings.tunExcludeUIDRange} placeholder="1000:9999" onDraft={(value) => draft('tunExcludeUIDRange', value)} onCommit={(value) => commit('tunExcludeUIDRange', value)}/>
                </div>
            </details>

            <details className="panel tunDetails">
                <summary>Android</summary>
                <div className="formPanel">
                    <AutoNumberListField label="包含 Android 用户" value={settings.tunIncludeAndroidUser} placeholder={'0\n10'} onDraft={(value) => draft('tunIncludeAndroidUser', value)} onCommit={(value) => commit('tunIncludeAndroidUser', value)}/>
                    <AutoListField label="包含应用包名" value={settings.tunIncludePackage} placeholder="com.android.chrome" onDraft={(value) => draft('tunIncludePackage', value)} onCommit={(value) => commit('tunIncludePackage', value)}/>
                    <AutoListField label="排除应用包名" value={settings.tunExcludePackage} placeholder="com.android.captiveportallogin" onDraft={(value) => draft('tunExcludePackage', value)} onCommit={(value) => commit('tunExcludePackage', value)}/>
                </div>
            </details>

            <details className="panel tunDetails">
                <summary>旧写法</summary>
                <div className="formPanel">
                    <AutoListField label="IPv4 路由网段" value={settings.tunInet4RouteAddress} placeholder={'0.0.0.0/1\n128.0.0.0/1'} onDraft={(value) => draft('tunInet4RouteAddress', value)} onCommit={(value) => commit('tunInet4RouteAddress', value)}/>
                    <AutoListField label="IPv6 路由网段" value={settings.tunInet6RouteAddress} placeholder={'::/1\n8000::/1'} onDraft={(value) => draft('tunInet6RouteAddress', value)} onCommit={(value) => commit('tunInet6RouteAddress', value)}/>
                    <AutoListField label="IPv4 排除网段" value={settings.tunInet4RouteExcludeAddress} placeholder="192.168.0.0/16" onDraft={(value) => draft('tunInet4RouteExcludeAddress', value)} onCommit={(value) => commit('tunInet4RouteExcludeAddress', value)}/>
                    <AutoListField label="IPv6 排除网段" value={settings.tunInet6RouteExcludeAddress} placeholder="fc00::/7" onDraft={(value) => draft('tunInet6RouteExcludeAddress', value)} onCommit={(value) => commit('tunInet6RouteExcludeAddress', value)}/>
                </div>
            </details>
        </section>
    );
}

function normalizeTunSettings(settings: Settings): Settings {
    const next = {...settings};
    if ((next.tunIncludeInterface || []).length > 0) next.tunExcludeInterface = [];
    if ((next.tunExcludeInterface || []).length > 0) next.tunIncludeInterface = [];
    return next;
}

function AutoTextField({label, value, placeholder, onDraft, onCommit}: {
    label: string;
    value: string;
    placeholder?: string;
    onDraft: (value: string) => void;
    onCommit: (value: string) => void;
}) {
    const [draft, setDraft] = useState(value || '');
    useEffect(() => setDraft(value || ''), [value]);
    return (
        <label className="field">
            <span>{label}</span>
            <input value={draft} placeholder={placeholder} onChange={(event) => {
                setDraft(event.target.value);
                onDraft(event.target.value);
            }} onBlur={() => onCommit(draft)} onKeyDown={(event) => {
                if (event.key === 'Enter') event.currentTarget.blur();
            }}/>
        </label>
    );
}

function AutoNumberField({label, value, placeholder, onCommit}: {
    label: string;
    value: number;
    placeholder?: string;
    onCommit: (value: number) => void;
}) {
    const [draft, setDraft] = useState(value ? String(value) : '');
    useEffect(() => setDraft(value ? String(value) : ''), [value]);
    const commit = () => {
        const next = Number(draft);
        onCommit(Number.isFinite(next) && next > 0 ? Math.floor(next) : 0);
    };
    return (
        <label className="field">
            <span>{label}</span>
            <input type="number" min="0" value={draft} placeholder={placeholder} onChange={(event) => setDraft(event.target.value)} onBlur={commit} onKeyDown={(event) => {
                if (event.key === 'Enter') event.currentTarget.blur();
            }}/>
        </label>
    );
}

function AutoListField({label, value, placeholder, onDraft, onCommit}: {
    label: string;
    value: string[];
    placeholder?: string;
    onDraft: (value: string[]) => void;
    onCommit: (value: string[]) => void;
}) {
    const [draft, setDraft] = useState(listToText(value));
    useEffect(() => setDraft(listToText(value)), [value]);
    return (
        <label className="field">
            <span>{label}</span>
            <textarea value={draft} placeholder={placeholder} onChange={(event) => {
                setDraft(event.target.value);
                onDraft(textToList(event.target.value));
            }} onBlur={() => onCommit(textToList(draft))}/>
        </label>
    );
}

function AutoNumberListField({label, value, placeholder, onDraft, onCommit}: {
    label: string;
    value: number[];
    placeholder?: string;
    onDraft: (value: number[]) => void;
    onCommit: (value: number[]) => void;
}) {
    const [draft, setDraft] = useState((value || []).join('\n'));
    useEffect(() => setDraft((value || []).join('\n')), [value]);
    return (
        <label className="field">
            <span>{label}</span>
            <textarea value={draft} placeholder={placeholder} onChange={(event) => {
                setDraft(event.target.value);
                onDraft(textToNumberList(event.target.value));
            }} onBlur={() => onCommit(textToNumberList(draft))}/>
        </label>
    );
}

function listToText(value: string[]) {
    return (value || []).join('\n');
}

function textToList(value: string) {
    return value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

function textToNumberList(value: string) {
    return value
        .split(/\r?\n/)
        .map((line) => Number(line.trim()))
        .filter((item) => Number.isInteger(item));
}
