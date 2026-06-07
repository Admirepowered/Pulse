import {FolderOpen, Image as ImageIcon, Save, X} from 'lucide-react';
import {Field, Toggle} from '../components/common';
import type {Translator} from '../i18n';
import type {Settings, WebDAVSettings} from '../types';

export function SettingsPage({settings, t, onChange, onApply, onSave, onOpenDir, onChooseBackground, onClearBackground}: {
    settings: Settings;
    t: Translator;
    onChange: (settings: Settings) => void;
    onApply: (settings: Settings) => void;
    onSave: () => void;
    onOpenDir: () => void;
    onChooseBackground: () => void;
    onClearBackground: () => void;
}) {
    const set = <K extends keyof Settings>(key: K, value: Settings[K], immediate = false) => {
        const next = {...settings, [key]: value};
        if (immediate) {
            onApply(next);
            return;
        }
        onChange(next);
    };
    const setWebDAV = <K extends keyof WebDAVSettings>(key: K, value: WebDAVSettings[K], immediate = false) => {
        const next = {...settings, webdav: {...settings.webdav, [key]: value}};
        if (immediate) {
            onApply(next);
            return;
        }
        onChange(next);
    };

    return (
        <section className="split">
            <article className="panel formPanel">
                <div className="panelHead"><h2>{t('core')}</h2></div>
                <div className="segmented">
                    {[
                        {id: 'embedded', label: t('embedded')},
                        {id: 'custom', label: t('custom')},
                    ].map((mode) => (
                        <button className={settings.coreMode === mode.id ? 'active' : ''} key={mode.id} onClick={() => set('coreMode', mode.id, true)}>
                            {mode.label}
                        </button>
                    ))}
                </div>
                <Field label={t('mihomoPath')} value={settings.corePath} onChange={(value) => set('corePath', value)}/>
                <Field label={t('apiAddress')} value={settings.apiBase} onChange={(value) => set('apiBase', value)}/>
                <Field label="Secret" value={settings.secret} onChange={(value) => set('secret', value)}/>
                <Field label="Mixed Port" type="number" value={String(settings.mixedPort)} onChange={(value) => set('mixedPort', Number(value) || 7890)}/>
                <div className="segmented">
                    {['rule', 'global', 'direct'].map((mode) => (
                        <button className={settings.mode === mode ? 'active' : ''} key={mode} onClick={() => set('mode', mode, true)}>
                            {mode}
                        </button>
                    ))}
                </div>
                <div className="segmented">
                    {['debug', 'info', 'warning', 'error', 'silent'].map((level) => (
                        <button className={settings.logLevel === level ? 'active' : ''} key={level} onClick={() => set('logLevel', level, true)}>
                            {level}
                        </button>
                    ))}
                </div>
                <Toggle label="Allow LAN" checked={settings.allowLan} onChange={(value) => set('allowLan', value, true)}/>
                <Toggle label="TUN" checked={settings.tunEnabled} onChange={(value) => set('tunEnabled', value, true)}/>
                <Toggle label={t('systemProxy')} checked={settings.systemProxy} onChange={(value) => set('systemProxy', value, true)}/>
                <Toggle label={t('autoStartCore')} checked={settings.autoStartCore} onChange={(value) => set('autoStartCore', value, true)}/>
                <Toggle label={t('autoStart')} checked={settings.autoStart} onChange={(value) => set('autoStart', value, true)}/>
                <div className="segmented">
                    {[
                        {id: 'minimize', label: t('closeMinimize')},
                        {id: 'exit', label: t('closeExit')},
                    ].map((mode) => (
                        <button className={settings.closeBehavior === mode.id ? 'active' : ''} key={mode.id} onClick={() => set('closeBehavior', mode.id, true)}>
                            {mode.label}
                        </button>
                    ))}
                </div>
                <div className="segmented">
                    {[
                        {id: 'zh', label: t('chinese')},
                        {id: 'en', label: t('english')},
                    ].map((language) => (
                        <button className={settings.language === language.id ? 'active' : ''} key={language.id} onClick={() => set('language', language.id, true)}>
                            {language.label}
                        </button>
                    ))}
                </div>
            </article>

            <div className="stack">
                <article className="panel formPanel">
                    <div className="panelHead"><h2>{t('appearance')}</h2></div>
                    <div className="backgroundPicker">
                        <div className="pathPreview" title={settings.backgroundPath || t('noBackground')}>
                            <ImageIcon size={17}/>
                            <span>{settings.backgroundPath || t('noBackground')}</span>
                        </div>
                        <div className="modalActions inline">
                            <button onClick={onChooseBackground}><ImageIcon size={17}/>{t('chooseImage')}</button>
                            <button disabled={!settings.backgroundPath} onClick={onClearBackground}><X size={17}/>{t('clear')}</button>
                        </div>
                    </div>
                    <label className="rangeField">
                        <span>{t('blur')} <strong>{settings.backgroundBlur || 0}px</strong></span>
                        <input
                            type="range"
                            min="0"
                            max="40"
                            step="1"
                            value={settings.backgroundBlur || 0}
                            onChange={(event) => set('backgroundBlur', Number(event.target.value))}
                        />
                    </label>
                    <label className="rangeField">
                        <span>{t('opacity')} <strong>{settings.backgroundOpacity ?? 62}%</strong></span>
                        <input
                            type="range"
                            min="0"
                            max="100"
                            step="1"
                            value={settings.backgroundOpacity ?? 62}
                            onChange={(event) => set('backgroundOpacity', Number(event.target.value))}
                        />
                    </label>
                </article>

                <article className="panel formPanel">
                    <div className="panelHead"><h2>{t('sync')}</h2></div>
                    <Toggle label="WebDAV" checked={settings.webdav.enabled} onChange={(value) => setWebDAV('enabled', value, true)}/>
                    <Field label="URL" value={settings.webdav.url} onChange={(value) => setWebDAV('url', value)}/>
                    <Field label={t('username')} value={settings.webdav.username} onChange={(value) => setWebDAV('username', value)}/>
                    <Field label={t('password')} value={settings.webdav.password} onChange={(value) => setWebDAV('password', value)}/>
                    <div className="modalActions inline">
                        <button onClick={onOpenDir}><FolderOpen size={17}/>{t('dataDirectory')}</button>
                        <button className="primary" onClick={onSave}><Save size={17}/>{t('saveSettings')}</button>
                    </div>
                </article>
            </div>
        </section>
    );
}
