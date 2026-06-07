import {FolderOpen} from 'lucide-react';
import {Toggle} from '../../components/common';
import type {Translator} from '../../i18n';
import type {Settings, WebDAVSettings} from '../../types';
import {AutoSaveField} from './AutoSaveField';

export function SyncSettingsPanel({settings, t, onDraft, onCommit, onApply, onOpenDir}: {
    settings: Settings;
    t: Translator;
    onDraft: (settings: Settings) => void;
    onCommit: (settings: Settings) => void;
    onApply: (settings: Settings) => void;
    onOpenDir: () => void;
}) {
    const draftWebDAV = <K extends keyof WebDAVSettings>(key: K, value: WebDAVSettings[K]) => {
        onDraft({...settings, webdav: {...settings.webdav, [key]: value}});
    };
    const commitWebDAV = <K extends keyof WebDAVSettings>(key: K, value: WebDAVSettings[K]) => {
        onCommit({...settings, webdav: {...settings.webdav, [key]: value}});
    };
    const applyWebDAV = <K extends keyof WebDAVSettings>(key: K, value: WebDAVSettings[K]) => {
        onApply({...settings, webdav: {...settings.webdav, [key]: value}});
    };

    return (
        <article className="panel formPanel">
            <div className="panelHead"><h2>{t('sync')}</h2></div>
            <Toggle label="WebDAV" checked={settings.webdav.enabled} onChange={(value) => applyWebDAV('enabled', value)}/>
            <AutoSaveField label="URL" value={settings.webdav.url} onDraft={(value) => draftWebDAV('url', value)} onCommit={(value) => commitWebDAV('url', value)}/>
            <AutoSaveField label={t('username')} value={settings.webdav.username} onDraft={(value) => draftWebDAV('username', value)} onCommit={(value) => commitWebDAV('username', value)}/>
            <AutoSaveField label={t('password')} value={settings.webdav.password} onDraft={(value) => draftWebDAV('password', value)} onCommit={(value) => commitWebDAV('password', value)}/>
            <div className="modalActions inline">
                <button onClick={onOpenDir}><FolderOpen size={17}/>{t('dataDirectory')}</button>
            </div>
        </article>
    );
}
