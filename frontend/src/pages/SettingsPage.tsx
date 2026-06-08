import {Download} from 'lucide-react';
import {AppearanceSettingsPanel} from './settings/AppearanceSettingsPanel';
import {CoreSettingsPanel} from './settings/CoreSettingsPanel';
import {SyncSettingsPanel} from './settings/SyncSettingsPanel';
import type {Translator} from '../i18n';
import type {BackgroundImage, Settings} from '../types';

export function SettingsPage({settings, backgrounds, t, onChange, onApply, onCommit, onOpenDir, onChooseBackground, onClearBackground, onSelectBackground, onDeleteBackground, onCheckUpdates}: {
    settings: Settings;
    backgrounds: BackgroundImage[];
    t: Translator;
    onChange: (settings: Settings) => void;
    onApply: (settings: Settings) => void;
    onCommit: (settings: Settings) => void;
    onOpenDir: () => void;
    onChooseBackground: () => void;
    onClearBackground: () => void;
    onSelectBackground: (id: string) => void;
    onDeleteBackground: (id: string) => void;
    onCheckUpdates: () => void;
}) {
    return (
        <section className="split">
            <CoreSettingsPanel
                settings={settings}
                t={t}
                onDraft={onChange}
                onCommit={onCommit}
                onApply={onApply}
            />

            <div className="stack">
                <AppearanceSettingsPanel
                    settings={settings}
                    backgrounds={backgrounds}
                    t={t}
                    onDraft={onChange}
                    onCommit={onCommit}
                    onChooseBackground={onChooseBackground}
                    onClearBackground={onClearBackground}
                    onSelectBackground={onSelectBackground}
                    onDeleteBackground={onDeleteBackground}
                />
                <SyncSettingsPanel
                    settings={settings}
                    t={t}
                    onDraft={onChange}
                    onCommit={onCommit}
                    onApply={onApply}
                    onOpenDir={onOpenDir}
                />
                <article className="panel">
                    <div className="panelHead">
                        <h2>{t('update')}</h2>
                    </div>
                    <button className="wide" onClick={onCheckUpdates}>
                        <Download size={17}/>{t('checkUpdates')}
                    </button>
                </article>
            </div>
        </section>
    );
}
