import {Plus, Save, X} from 'lucide-react';
import {useEffect, useState} from 'react';
import type {Translator} from '../i18n';
import type {ProxyNodeConfig} from '../types';

const PROTOCOL_FIELDS: Record<string, string[]> = {
    ss: ['server', 'port', 'cipher', 'password', 'udp'],
    vmess: ['server', 'port', 'uuid', 'alterId', 'cipher', 'network', 'wsHost', 'wsPath', 'sni', 'skipVerify', 'udp'],
    vless: ['server', 'port', 'uuid', 'network', 'wsHost', 'wsPath', 'sni', 'skipVerify', 'udp'],
    trojan: ['server', 'port', 'password', 'network', 'wsHost', 'wsPath', 'sni', 'skipVerify', 'udp'],
    socks5: ['server', 'port', 'username', 'password', 'udp'],
    http: ['server', 'port', 'username', 'password'],
    hysteria2: ['server', 'port', 'password', 'sni', 'skipVerify', 'udp'],
    tuic: ['server', 'port', 'uuid', 'password', 'sni', 'skipVerify', 'udp'],
};

const PROTOCOLS = Object.keys(PROTOCOL_FIELDS);
const NETWORK_OPTIONS = ['tcp', 'ws', 'grpc', 'h2'];
const CIPHER_OPTIONS = ['auto', 'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', 'none', '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'];

function autoName(type: string, server: string, port: number): string {
    if (!type || !server) return '';
    const abbr: Record<string, string> = {ss: 'SS', vmess: 'VM', vless: 'VL', trojan: 'TJ', socks5: 'S5', http: 'HTTP', hysteria2: 'HY2', tuic: 'TUIC'};
    return `${abbr[type] || type.toUpperCase()} ${server}:${port || ''}`;
}

function Field({label, children}: {label: string; children: React.ReactNode}) {
    return <label className="field">{label}{children}</label>;
}

export function NodeEditorModal({t, onSave, onClose}: {
    t: Translator;
    onSave: (node: ProxyNodeConfig) => void;
    onClose: () => void;
}) {
    const [node, setNode] = useState<ProxyNodeConfig>({name: '', type: 'ss', server: '', port: 0, udp: false});
    const [showFields, setShowFields] = useState<string[]>(PROTOCOL_FIELDS.ss);

    useEffect(() => {
        setShowFields(PROTOCOL_FIELDS[node.type] || PROTOCOL_FIELDS.ss);
    }, [node.type]);

    const set = (key: keyof ProxyNodeConfig, value: string | number | boolean) => {
        setNode((prev) => {
            const next = {...prev, [key]: value};
            if (key === 'type' || key === 'server' || key === 'port') {
                next.name = autoName(next.type, next.server, next.port);
            }
            return next;
        });
    };

    const visible = (key: string) => showFields.includes(key);

    return (
        <div className="modalBackdrop">
            <div className="modal">
                <div className="panelHead">
                    <div>
                        <h2>{t('addNode')}</h2>
                        <span>{t('protocol')}</span>
                    </div>
                    <button className="iconButton" onClick={onClose}><X size={18}/></button>
                </div>
                <div className="nodeEditorForm">
                    <Field label={t('protocol')}>
                        <select className="selectControl wideSelect" value={node.type} onChange={(e) => set('type', e.target.value)}>
                            {PROTOCOLS.map((p) => <option key={p} value={p}>{p}</option>)}
                        </select>
                    </Field>
                    <Field label={t('name')}>
                        <input type="text" value={node.name} onChange={(e) => set('name', e.target.value)} placeholder={autoName(node.type, node.server, node.port)}/>
                    </Field>
                    {visible('server') && <Field label={t('server')}><input type="text" value={node.server} onChange={(e) => set('server', e.target.value)}/></Field>}
                    {visible('port') && <Field label={t('port')}><input type="number" value={node.port || ''} onChange={(e) => set('port', Number(e.target.value))}/></Field>}
                    {visible('password') && <Field label={t('password')}><input type="text" value={node.password || ''} onChange={(e) => set('password', e.target.value)}/></Field>}
                    {visible('cipher') && (
                        <Field label={t('cipher')}>
                            <select className="selectControl wideSelect" value={node.cipher || 'auto'} onChange={(e) => set('cipher', e.target.value)}>
                                {CIPHER_OPTIONS.map((c) => <option key={c} value={c}>{c}</option>)}
                            </select>
                        </Field>
                    )}
                    {visible('uuid') && <Field label={t('uuid')}><input type="text" value={node.uuid || ''} onChange={(e) => set('uuid', e.target.value)}/></Field>}
                    {visible('alterId') && <Field label={t('alterId')}><input type="number" value={node.alterId || 0} onChange={(e) => set('alterId', Number(e.target.value))}/></Field>}
                    {visible('username') && <Field label={t('username')}><input type="text" value={node.username || ''} onChange={(e) => set('username', e.target.value)}/></Field>}
                    {visible('network') && (
                        <Field label={t('network')}>
                            <select className="selectControl wideSelect" value={node.network || 'tcp'} onChange={(e) => set('network', e.target.value)}>
                                {NETWORK_OPTIONS.map((n) => <option key={n} value={n}>{n}</option>)}
                            </select>
                        </Field>
                    )}
                    {visible('wsHost') && <Field label={t('wsHost')}><input type="text" value={node.wsHost || ''} onChange={(e) => set('wsHost', e.target.value)}/></Field>}
                    {visible('wsPath') && <Field label={t('wsPath')}><input type="text" value={node.wsPath || ''} onChange={(e) => set('wsPath', e.target.value)}/></Field>}
                    {visible('sni') && <Field label={t('sni')}><input type="text" value={node.sni || ''} onChange={(e) => set('sni', e.target.value)}/></Field>}
                    {visible('skipVerify') && (
                        <label className="toggle">
                            <span>{t('skipVerify')}</span>
                            <input type="checkbox" checked={node.skipVerify || false} onChange={(e) => set('skipVerify', e.target.checked)}/>
                            <i/>
                        </label>
                    )}
                    {visible('udp') && (
                        <label className="toggle">
                            <span>{t('udp')}</span>
                            <input type="checkbox" checked={node.udp || false} onChange={(e) => set('udp', e.target.checked)}/>
                            <i/>
                        </label>
                    )}
                </div>
                <div className="modalActions">
                    <button onClick={onClose}>{t('cancel')}</button>
                    <button className="primary" onClick={() => onSave(node)} disabled={!node.type || !node.server || !node.port}>
                        <Plus size={17}/>{t('addNode')}
                    </button>
                </div>
            </div>
        </div>
    );
}
