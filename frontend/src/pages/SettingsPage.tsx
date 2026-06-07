import {FolderOpen, Image as ImageIcon, Save, X} from 'lucide-react';
import {Field, Toggle} from '../components/common';
import type {Settings, WebDAVSettings} from '../types';

export function SettingsPage({settings, onChange, onApply, onSave, onOpenDir, onChooseBackground, onClearBackground}: {
    settings: Settings;
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
                <div className="panelHead"><h2>Core</h2></div>
                <div className="segmented">
                    {[
                        {id: 'embedded', label: '内嵌'},
                        {id: 'custom', label: '自定义'},
                    ].map((mode) => (
                        <button className={settings.coreMode === mode.id ? 'active' : ''} key={mode.id} onClick={() => set('coreMode', mode.id, true)}>
                            {mode.label}
                        </button>
                    ))}
                </div>
                <Field label="mihomo 路径" value={settings.corePath} onChange={(value) => set('corePath', value)}/>
                <Field label="API 地址" value={settings.apiBase} onChange={(value) => set('apiBase', value)}/>
                <Field label="Secret" value={settings.secret} onChange={(value) => set('secret', value)}/>
                <Field label="Mixed Port" type="number" value={String(settings.mixedPort)} onChange={(value) => set('mixedPort', Number(value) || 7890)}/>
                <div className="segmented">
                    {['rule', 'global', 'direct'].map((mode) => (
                        <button className={settings.mode === mode ? 'active' : ''} key={mode} onClick={() => set('mode', mode, true)}>
                            {mode}
                        </button>
                    ))}
                </div>
                <Toggle label="Allow LAN" checked={settings.allowLan} onChange={(value) => set('allowLan', value, true)}/>
                <Toggle label="TUN" checked={settings.tunEnabled} onChange={(value) => set('tunEnabled', value, true)}/>
                <Toggle label="系统代理" checked={settings.systemProxy} onChange={(value) => set('systemProxy', value, true)}/>
                <Toggle label="启动时启动核心" checked={settings.autoStartCore} onChange={(value) => set('autoStartCore', value, true)}/>
                <Toggle label="开机启动" checked={settings.autoStart} onChange={(value) => set('autoStart', value, true)}/>
                <div className="segmented">
                    {[
                        {id: 'minimize', label: '关闭时最小化'},
                        {id: 'exit', label: '关闭时退出'},
                    ].map((mode) => (
                        <button className={settings.closeBehavior === mode.id ? 'active' : ''} key={mode.id} onClick={() => set('closeBehavior', mode.id, true)}>
                            {mode.label}
                        </button>
                    ))}
                </div>
            </article>

            <div className="stack">
                <article className="panel formPanel">
                    <div className="panelHead"><h2>外观</h2></div>
                    <div className="backgroundPicker">
                        <div className="pathPreview" title={settings.backgroundPath || '未选择背景图片'}>
                            <ImageIcon size={17}/>
                            <span>{settings.backgroundPath || '未选择背景图片'}</span>
                        </div>
                        <div className="modalActions inline">
                            <button onClick={onChooseBackground}><ImageIcon size={17}/>选择图片</button>
                            <button disabled={!settings.backgroundPath} onClick={onClearBackground}><X size={17}/>清除</button>
                        </div>
                    </div>
                    <label className="rangeField">
                        <span>虚化程度 <strong>{settings.backgroundBlur || 0}px</strong></span>
                        <input
                            type="range"
                            min="0"
                            max="40"
                            step="1"
                            value={settings.backgroundBlur || 0}
                            onChange={(event) => set('backgroundBlur', Number(event.target.value))}
                        />
                    </label>
                </article>

                <article className="panel formPanel">
                    <div className="panelHead"><h2>同步</h2></div>
                    <Toggle label="WebDAV" checked={settings.webdav.enabled} onChange={(value) => setWebDAV('enabled', value, true)}/>
                    <Field label="URL" value={settings.webdav.url} onChange={(value) => setWebDAV('url', value)}/>
                    <Field label="用户名" value={settings.webdav.username} onChange={(value) => setWebDAV('username', value)}/>
                    <Field label="密码" value={settings.webdav.password} onChange={(value) => setWebDAV('password', value)}/>
                    <div className="modalActions inline">
                        <button onClick={onOpenDir}><FolderOpen size={17}/>数据目录</button>
                        <button className="primary" onClick={onSave}><Save size={17}/>保存设置</button>
                    </div>
                </article>
            </div>
        </section>
    );
}
