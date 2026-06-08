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
    const interfaceOptions = useMemo(() => interfaces.map((item) => ({
        value: item.name,
        label: `${item.displayName || item.name}${item.addresses?.length ? ` - ${item.addresses[0]}` : ''}`,
    })), [interfaces]);

    const commitIncludeInterface = (value: string[]) => onCommit(normalizeTunSettings({...settings, tunIncludeInterface: value, tunExcludeInterface: value.length ? [] : settings.tunExcludeInterface}));
    const commitExcludeInterface = (value: string[]) => onCommit(normalizeTunSettings({...settings, tunExcludeInterface: value, tunIncludeInterface: value.length ? [] : settings.tunIncludeInterface}));

    return (
        <section className="tunPage">
            <article className="panel formPanel tunPrimaryPanel">
                <div className="panelHead"><h2>TUN</h2></div>
                <div className="tunToggleGrid">
                    <Toggle label="enable" checked={settings.tunEnabled} onChange={(value) => commit('tunEnabled', value)}/>
                    <Toggle label="auto-route" checked={settings.tunAutoRoute} onChange={(value) => commit('tunAutoRoute', value)}/>
                    <Toggle label="auto-redirect" checked={settings.tunAutoRedirect} onChange={(value) => commit('tunAutoRedirect', value)}/>
                    <Toggle label="auto-detect-interface" checked={settings.tunAutoDetectInterface} onChange={(value) => commit('tunAutoDetectInterface', value)}/>
                    <Toggle label="strict-route" checked={settings.tunStrictRoute} onChange={(value) => commit('tunStrictRoute', value)}/>
                    <Toggle label="endpoint-independent-nat" checked={settings.tunEndpointIndependentNAT} onChange={(value) => commit('tunEndpointIndependentNAT', value)}/>
                </div>
                <label className="field">
                    <span>stack</span>
                    <select className="selectControl wideSelect" value={settings.tunStack || 'mixed'} onChange={(event) => commit('tunStack', event.target.value)}>
                        {stacks.map((stack) => <option key={stack.id} value={stack.id}>{stack.label}</option>)}
                    </select>
                </label>
                <div className="tunFieldGrid">
                    <AutoTextField label="device" value={settings.tunDevice} placeholder="utun0" onDraft={(value) => draft('tunDevice', value)} onCommit={(value) => commit('tunDevice', value)}/>
                    <AutoNumberField label="mtu" value={settings.tunMTU} placeholder="9000" onCommit={(value) => commit('tunMTU', value)}/>
                    <AutoNumberField label="udp-timeout" value={settings.tunUDPTimeout} placeholder="300" onCommit={(value) => commit('tunUDPTimeout', value)}/>
                </div>
                <AutoTextField label="inet6-address" value={settings.tunInet6Address} placeholder="fdfe:dcba:9876::1/126" onDraft={(value) => draft('tunInet6Address', value)} onCommit={(value) => commit('tunInet6Address', value)}/>
                <AutoListField label="dns-hijack" value={settings.tunDNSHijack} placeholder={'any:53\ntcp://any:53'} onDraft={(value) => draft('tunDNSHijack', value)} onCommit={(value) => commit('tunDNSHijack', value)}/>
            </article>

            <article className="panel formPanel">
                <div className="panelHead"><h2>Routing</h2></div>
                <AutoListField label="route-address" value={settings.tunRouteAddress} placeholder={'0.0.0.0/1\n128.0.0.0/1\n::/1\n8000::/1'} onDraft={(value) => draft('tunRouteAddress', value)} onCommit={(value) => commit('tunRouteAddress', value)}/>
                <AutoListField label="route-exclude-address" value={settings.tunRouteExcludeAddress} placeholder={'192.168.0.0/16\nfc00::/7'} onDraft={(value) => draft('tunRouteExcludeAddress', value)} onCommit={(value) => commit('tunRouteExcludeAddress', value)}/>
            </article>

            <article className="panel formPanel">
                <div className="panelHead"><h2>Interfaces</h2></div>
                <label className="field">
                    <span>add include-interface</span>
                    <select className="selectControl wideSelect" value="" onChange={(event) => {
                        const value = event.target.value;
                        if (!value) return;
                        const next = Array.from(new Set([...(settings.tunIncludeInterface || []), value]));
                        commitIncludeInterface(next);
                    }}>
                        <option value="">select interface</option>
                        {interfaceOptions.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
                    </select>
                </label>
                <AutoListField label="include-interface" value={settings.tunIncludeInterface} onDraft={(value) => draft('tunIncludeInterface', value)} onCommit={commitIncludeInterface}/>
                <AutoListField label="exclude-interface" value={settings.tunExcludeInterface} onDraft={(value) => draft('tunExcludeInterface', value)} onCommit={commitExcludeInterface}/>
            </article>

            <details className="panel tunDetails">
                <summary>Linux</summary>
                <div className="formPanel">
                    <Toggle label="gso" checked={settings.tunGSO} onChange={(value) => commit('tunGSO', value)}/>
                    <div className="tunFieldGrid">
                        <AutoNumberField label="gso-max-size" value={settings.tunGSOMaxSize} placeholder="65536" onCommit={(value) => commit('tunGSOMaxSize', value)}/>
                        <AutoNumberField label="iproute2-table-index" value={settings.tunIPRoute2TableIndex} placeholder="2022" onCommit={(value) => commit('tunIPRoute2TableIndex', value)}/>
                        <AutoNumberField label="iproute2-rule-index" value={settings.tunIPRoute2RuleIndex} placeholder="9000" onCommit={(value) => commit('tunIPRoute2RuleIndex', value)}/>
                    </div>
                    <AutoListField label="route-address-set" value={settings.tunRouteAddressSet} placeholder="ruleset-1" onDraft={(value) => draft('tunRouteAddressSet', value)} onCommit={(value) => commit('tunRouteAddressSet', value)}/>
                    <AutoListField label="route-exclude-address-set" value={settings.tunRouteExcludeAddressSet} placeholder="ruleset-2" onDraft={(value) => draft('tunRouteExcludeAddressSet', value)} onCommit={(value) => commit('tunRouteExcludeAddressSet', value)}/>
                    <AutoNumberListField label="include-uid" value={settings.tunIncludeUID} placeholder="0" onDraft={(value) => draft('tunIncludeUID', value)} onCommit={(value) => commit('tunIncludeUID', value)}/>
                    <AutoListField label="include-uid-range" value={settings.tunIncludeUIDRange} placeholder="1000:9999" onDraft={(value) => draft('tunIncludeUIDRange', value)} onCommit={(value) => commit('tunIncludeUIDRange', value)}/>
                    <AutoNumberListField label="exclude-uid" value={settings.tunExcludeUID} placeholder="1000" onDraft={(value) => draft('tunExcludeUID', value)} onCommit={(value) => commit('tunExcludeUID', value)}/>
                    <AutoListField label="exclude-uid-range" value={settings.tunExcludeUIDRange} placeholder="1000:9999" onDraft={(value) => draft('tunExcludeUIDRange', value)} onCommit={(value) => commit('tunExcludeUIDRange', value)}/>
                </div>
            </details>

            <details className="panel tunDetails">
                <summary>Android</summary>
                <div className="formPanel">
                    <AutoNumberListField label="include-android-user" value={settings.tunIncludeAndroidUser} placeholder={'0\n10'} onDraft={(value) => draft('tunIncludeAndroidUser', value)} onCommit={(value) => commit('tunIncludeAndroidUser', value)}/>
                    <AutoListField label="include-package" value={settings.tunIncludePackage} placeholder="com.android.chrome" onDraft={(value) => draft('tunIncludePackage', value)} onCommit={(value) => commit('tunIncludePackage', value)}/>
                    <AutoListField label="exclude-package" value={settings.tunExcludePackage} placeholder="com.android.captiveportallogin" onDraft={(value) => draft('tunExcludePackage', value)} onCommit={(value) => commit('tunExcludePackage', value)}/>
                </div>
            </details>

            <details className="panel tunDetails">
                <summary>Legacy</summary>
                <div className="formPanel">
                    <AutoListField label="inet4-route-address" value={settings.tunInet4RouteAddress} placeholder={'0.0.0.0/1\n128.0.0.0/1'} onDraft={(value) => draft('tunInet4RouteAddress', value)} onCommit={(value) => commit('tunInet4RouteAddress', value)}/>
                    <AutoListField label="inet6-route-address" value={settings.tunInet6RouteAddress} placeholder={'::/1\n8000::/1'} onDraft={(value) => draft('tunInet6RouteAddress', value)} onCommit={(value) => commit('tunInet6RouteAddress', value)}/>
                    <AutoListField label="inet4-route-exclude-address" value={settings.tunInet4RouteExcludeAddress} placeholder="192.168.0.0/16" onDraft={(value) => draft('tunInet4RouteExcludeAddress', value)} onCommit={(value) => commit('tunInet4RouteExcludeAddress', value)}/>
                    <AutoListField label="inet6-route-exclude-address" value={settings.tunInet6RouteExcludeAddress} placeholder="fc00::/7" onDraft={(value) => draft('tunInet6RouteExcludeAddress', value)} onCommit={(value) => commit('tunInet6RouteExcludeAddress', value)}/>
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
