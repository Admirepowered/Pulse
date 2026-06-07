import {Toggle} from '../../components/common';
import type {Translator} from '../../i18n';
import type {NetworkInterface, Settings} from '../../types';

export function TunSettingsPanel({settings, interfaces, t, onApply}: {
    settings: Settings;
    interfaces: NetworkInterface[];
    t: Translator;
    onApply: (settings: Settings) => void;
}) {
    return (
        <article className="panel formPanel">
            <div className="panelHead"><h2>TUN</h2></div>
            <Toggle label={t('enable')} checked={settings.tunEnabled} onChange={(value) => onApply({...settings, tunEnabled: value})}/>
            <label className="field">
                <span>网卡</span>
                <select
                    className="selectControl wideSelect"
                    value={settings.tunInterface || ''}
                    onChange={(event) => onApply({...settings, tunInterface: event.target.value})}
                >
                    <option value="">自动检测</option>
                    {interfaces.map((item) => (
                        <option key={item.name} value={item.name}>
                            {item.displayName || item.name}{item.addresses?.length ? ` - ${item.addresses[0]}` : ''}
                        </option>
                    ))}
                </select>
            </label>
        </article>
    );
}
