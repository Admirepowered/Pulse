import {Link, Save, X} from 'lucide-react';
import {useEffect, useState} from 'react';
import type {Translator} from '../i18n';
import type {RelayChainConfig} from '../types';

const GROUP_TYPES = ['select', 'url-test', 'fallback', 'load-balance'];

export function RelayChainModal({t, proxyNames, onSave, onClose}: {
    t: Translator;
    proxyNames: string[];
    onSave: (config: RelayChainConfig) => void;
    onClose: () => void;
}) {
    const [config, setConfig] = useState<RelayChainConfig>({name: '', node1: '', node2: ''});

    const set = (key: keyof RelayChainConfig, value: string) => {
        setConfig((prev) => ({...prev, [key]: value}));
    };

    const filteredNode1 = proxyNames.filter((n) => n !== config.node2);
    const filteredNode2 = proxyNames.filter((n) => n !== config.node1);

    return (
        <div className="modalBackdrop">
            <div className="modal">
                <div className="panelHead">
                    <div>
                        <h2>{t('createChain')}</h2>
                        <span>{t('chainName')}</span>
                    </div>
                    <button className="iconButton" onClick={onClose}><X size={18}/></button>
                </div>
                <div className="chainForm">
                    <label className="field">
                        {t('chainName')}
                        <input type="text" value={config.name} onChange={(e) => set('name', e.target.value)} placeholder="MyChain"/>
                    </label>
                    <label className="field">
                        {t('firstNode')}
                        <select className="selectControl wideSelect" value={config.node1} onChange={(e) => set('node1', e.target.value)}>
                            <option value="">-- {t('firstNode')} --</option>
                            {filteredNode1.map((name) => <option key={name} value={name}>{name}</option>)}
                        </select>
                    </label>
                    <label className="field">
                        {t('secondNode')}
                        <select className="selectControl wideSelect" value={config.node2} onChange={(e) => set('node2', e.target.value)}>
                            <option value="">-- {t('secondNode')} --</option>
                            {filteredNode2.map((name) => <option key={name} value={name}>{name}</option>)}
                        </select>
                    </label>
                </div>
                <div className="modalActions">
                    <button onClick={onClose}>{t('cancel')}</button>
                    <button className="primary" onClick={() => onSave(config)} disabled={!config.name || !config.node1 || !config.node2}>
                        <Link size={17}/>{t('createChain')}
                    </button>
                </div>
            </div>
        </div>
    );
}
