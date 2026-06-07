import {Check, Cloud, Link2, RefreshCcw, SquarePen, Trash2, Upload} from 'lucide-react';
import {Field, SubscriptionUsage, formatTime} from '../components/common';
import type {Profile, ProviderRow, RuntimeState} from '../types';

export function ProfilesPage({
    snapshot,
    providers,
    profileName,
    profileURL,
    importName,
    importContent,
    onProfileNameChange,
    onProfileURLChange,
    onImportNameChange,
    onImportContentChange,
    onOpenGithub,
    onActivate,
    onEdit,
    onUpdateProfile,
    onDeleteProfile,
    onUpdateProvider,
    onAddSubscription,
    onImportProfile,
}: {
    snapshot: RuntimeState;
    providers: ProviderRow[];
    profileName: string;
    profileURL: string;
    importName: string;
    importContent: string;
    onProfileNameChange: (value: string) => void;
    onProfileURLChange: (value: string) => void;
    onImportNameChange: (value: string) => void;
    onImportContentChange: (value: string) => void;
    onOpenGithub: () => void;
    onActivate: (id: string) => void;
    onEdit: (profile: Profile) => void;
    onUpdateProfile: (id: string) => void;
    onDeleteProfile: (id: string) => void;
    onUpdateProvider: (name: string) => void;
    onAddSubscription: () => void;
    onImportProfile: () => void;
}) {
    return (
        <section className="split">
            <div className="stack">
                <article className="panel">
                    <div className="panelHead">
                        <h2>Profiles</h2>
                        <button className="ghost" onClick={onOpenGithub}>
                            <Link2 size={16}/>GitHub
                        </button>
                    </div>
                    <div className="profileList">
                        {snapshot.profiles.map((profile) => (
                            <div className="profileRow" key={profile.id}>
                                <div>
                                    <strong>{profile.name}</strong>
                                    <span>{profile.type} · {formatTime(profile.updatedAt)}</span>
                                    <SubscriptionUsage info={profile.subscription}/>
                                </div>
                                <div className="rowActions">
                                    <button title="启用" onClick={() => onActivate(profile.id)}>
                                        <Check size={16}/>
                                    </button>
                                    <button title="编辑" onClick={() => onEdit(profile)}>
                                        <SquarePen size={16}/>
                                    </button>
                                    <button title="更新" onClick={() => onUpdateProfile(profile.id)}>
                                        <RefreshCcw size={16}/>
                                    </button>
                                    <button title="删除" onClick={() => onDeleteProfile(profile.id)}>
                                        <Trash2 size={16}/>
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                </article>

                <article className="panel">
                    <div className="panelHead"><h2>Proxy Providers</h2></div>
                    <div className="table">
                        {providers.map((provider) => (
                            <div className="tableRow" key={provider.name}>
                                <span>{provider.name}</span>
                                <span>{provider.vehicle || 'provider'}</span>
                                <span>{provider.proxies} 节点</span>
                                <button onClick={() => onUpdateProvider(provider.name)}>
                                    <RefreshCcw size={15}/>更新
                                </button>
                            </div>
                        ))}
                    </div>
                </article>
            </div>

            <div className="stack">
                <article className="panel">
                    <div className="panelHead"><h2>订阅</h2></div>
                    <Field label="名称（可选）" value={profileName} onChange={onProfileNameChange} placeholder="留空时自动从远程订阅推断"/>
                    <Field label="URL" value={profileURL} onChange={onProfileURLChange} placeholder="https://example.com/profile.yaml"/>
                    <button className="primary wide" onClick={onAddSubscription}>
                        <Cloud size={17}/>添加订阅
                    </button>
                </article>

                <article className="panel">
                    <div className="panelHead"><h2>本地 YAML</h2></div>
                    <Field label="名称" value={importName} onChange={onImportNameChange}/>
                    <textarea value={importContent} onChange={(event) => onImportContentChange(event.target.value)} spellCheck={false}/>
                    <button className="wide" onClick={onImportProfile}>
                        <Upload size={17}/>导入
                    </button>
                </article>
            </div>
        </section>
    );
}
