import {Image as ImageIcon, X} from 'lucide-react';
import type {Translator} from '../../i18n';
import type {BackgroundImage, Settings} from '../../types';

export function AppearanceSettingsPanel({settings, backgrounds, t, onDraft, onCommit, onChooseBackground, onClearBackground, onSelectBackground, onDeleteBackground}: {
    settings: Settings;
    backgrounds: BackgroundImage[];
    t: Translator;
    onDraft: (settings: Settings) => void;
    onCommit: (settings: Settings) => void;
    onChooseBackground: () => void;
    onClearBackground: () => void;
    onSelectBackground: (id: string) => void;
    onDeleteBackground: (id: string) => void;
}) {
    const draft = <K extends keyof Settings>(key: K, value: Settings[K]) => onDraft({...settings, [key]: value});
    const commit = <K extends keyof Settings>(key: K, value: Settings[K]) => onCommit({...settings, [key]: value});

    return (
        <article className="panel formPanel">
            <div className="panelHead"><h2>{t('appearance')}</h2></div>
            <label className="field">
                <span>{t('themeMode')}</span>
                <div className="segmented">
                    {[
                        {id: 'light', label: t('lightTheme')},
                        {id: 'dark', label: t('darkTheme')},
                        {id: 'system', label: t('systemTheme')},
                    ].map((theme) => (
                        <button className={settings.theme === theme.id ? 'active' : ''} key={theme.id} onClick={() => onCommit({...settings, theme: theme.id})}>
                            {theme.label}
                        </button>
                    ))}
                </div>
            </label>
            <div className="backgroundPicker">
                <div className="pathPreview">
                    <ImageIcon size={17}/>
                    <span>{backgrounds.find((item) => item.id === settings.backgroundPath)?.name || t('noBackground')}</span>
                </div>
                <div className="backgroundList">
                    {backgrounds.map((item) => (
                        <div className={item.id === settings.backgroundPath ? 'backgroundItem active' : 'backgroundItem'} key={item.id}>
                            <button onClick={() => onSelectBackground(item.id)}>{item.name}</button>
                            <button className="iconButton" title={t('delete')} onClick={() => onDeleteBackground(item.id)}>
                                <X size={14}/>
                            </button>
                        </div>
                    ))}
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
                    onChange={(event) => draft('backgroundBlur', Number(event.target.value))}
                    onMouseUp={(event) => commit('backgroundBlur', Number(event.currentTarget.value))}
                    onTouchEnd={(event) => commit('backgroundBlur', Number(event.currentTarget.value))}
                    onBlur={(event) => commit('backgroundBlur', Number(event.currentTarget.value))}
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
                    onChange={(event) => draft('backgroundOpacity', Number(event.target.value))}
                    onMouseUp={(event) => commit('backgroundOpacity', Number(event.currentTarget.value))}
                    onTouchEnd={(event) => commit('backgroundOpacity', Number(event.currentTarget.value))}
                    onBlur={(event) => commit('backgroundOpacity', Number(event.currentTarget.value))}
                />
            </label>
        </article>
    );
}
