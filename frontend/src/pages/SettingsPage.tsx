import {AppearanceSettingsPanel} from './settings/AppearanceSettingsPanel';
import {CoreSettingsPanel} from './settings/CoreSettingsPanel';
import {SyncSettingsPanel} from './settings/SyncSettingsPanel';
import type {Translator} from '../i18n';
import type {Settings} from '../types';

export function SettingsPage({settings, t, onChange, onApply, onCommit, onOpenDir, onChooseBackground, onClearBackground}: {
    settings: Settings;
    t: Translator;
    onChange: (settings: Settings) => void;
    onApply: (settings: Settings) => void;
    onCommit: (settings: Settings) => void;
    onOpenDir: () => void;
    onChooseBackground: () => void;
    onClearBackground: () => void;
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
                    t={t}
                    onDraft={onChange}
                    onCommit={onCommit}
                    onChooseBackground={onChooseBackground}
                    onClearBackground={onClearBackground}
                />
                <SyncSettingsPanel
                    settings={settings}
                    t={t}
                    onDraft={onChange}
                    onCommit={onCommit}
                    onApply={onApply}
                    onOpenDir={onOpenDir}
                />
            </div>
        </section>
    );
}
