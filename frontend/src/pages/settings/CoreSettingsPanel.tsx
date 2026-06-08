import {AutoSaveField} from './AutoSaveField';
import {Toggle} from '../../components/common';
import type {Translator} from '../../i18n';
import type {Settings} from '../../types';

const clashModes = [
    {id: 'rule', label: '规则'},
    {id: 'global', label: '全局'},
    {id: 'direct', label: '直连'},
] as const;

export function CoreSettingsPanel({settings, platform, t, onDraft, onCommit, onApply}: {
    settings: Settings;
    platform: string;
    t: Translator;
    onDraft: (settings: Settings) => void;
    onCommit: (settings: Settings) => void;
    onApply: (settings: Settings) => void;
}) {
    const draft = <K extends keyof Settings>(key: K, value: Settings[K]) => onDraft({...settings, [key]: value});
    const commit = <K extends keyof Settings>(key: K, value: Settings[K]) => onCommit({...settings, [key]: value});
    const apply = <K extends keyof Settings>(key: K, value: Settings[K]) => onApply({...settings, [key]: value});
    const commitMixedPort = (value: string) => {
        const port = Number(value);
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
            return String(settings.mixedPort || 7890);
        }
        commit('mixedPort', port);
    };
    const coreModes = [
        {id: 'embedded', label: t('embedded')},
        ...(platform === 'windows' || settings.coreMode === 'service' ? [{id: 'service', label: t('serviceCore')}] : []),
        {id: 'custom', label: t('custom')},
    ];

    return (
        <article className="panel formPanel">
            <div className="panelHead"><h2>{t('core')}</h2></div>
            <div className="segmented">
                {coreModes.map((mode) => (
                    <button className={settings.coreMode === mode.id ? 'active' : ''} key={mode.id} onClick={() => apply('coreMode', mode.id)}>
                        {mode.label}
                    </button>
                ))}
            </div>
            {settings.coreMode === 'custom' && (
                <>
                    <AutoSaveField label={t('mihomoPath')} value={settings.corePath} onDraft={(value) => draft('corePath', value)} onCommit={(value) => commit('corePath', value)}/>
                    <AutoSaveField label={t('apiAddress')} value={settings.apiBase} onDraft={(value) => draft('apiBase', value)} onCommit={(value) => commit('apiBase', value)}/>
                </>
            )}
            <AutoSaveField label="Secret" value={settings.secret} onDraft={(value) => draft('secret', value)} onCommit={(value) => commit('secret', value)}/>
            <AutoSaveField label="Mixed Port" type="number" value={String(settings.mixedPort || 7890)} onCommit={commitMixedPort}/>
            <AutoSaveField label={t('delayTestUrl')} value={settings.delayTestUrl} onDraft={(value) => draft('delayTestUrl', value)} onCommit={(value) => commit('delayTestUrl', value)}/>
            <div className="segmented">
                {clashModes.map((mode) => (
                    <button className={settings.mode === mode.id ? 'active' : ''} key={mode.id} onClick={() => apply('mode', mode.id)}>
                        {mode.label}
                    </button>
                ))}
            </div>
            <div className="segmented">
                {['debug', 'info', 'warning', 'error', 'silent'].map((level) => (
                    <button className={settings.logLevel === level ? 'active' : ''} key={level} onClick={() => apply('logLevel', level)}>
                        {level}
                    </button>
                ))}
            </div>
            <Toggle label={t('autoStartCore')} checked={settings.autoStartCore} onChange={(value) => apply('autoStartCore', value)}/>
            <div className="segmented">
                {[
                    {id: 'minimize', label: t('closeMinimize')},
                    {id: 'exit', label: t('closeExit')},
                ].map((mode) => (
                    <button className={settings.closeBehavior === mode.id ? 'active' : ''} key={mode.id} onClick={() => apply('closeBehavior', mode.id)}>
                        {mode.label}
                    </button>
                ))}
            </div>
            <div className="segmented">
                {[
                    {id: 'zh', label: t('chinese')},
                    {id: 'en', label: t('english')},
                ].map((language) => (
                    <button className={settings.language === language.id ? 'active' : ''} key={language.id} onClick={() => apply('language', language.id)}>
                        {language.label}
                    </button>
                ))}
            </div>
        </article>
    );
}
