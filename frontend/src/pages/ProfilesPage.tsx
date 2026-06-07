import {Cloud, Link2, RefreshCcw, SquarePen, Trash2, Upload} from 'lucide-react';
import {useState} from 'react';
import {Field, SubscriptionUsage, Toggle, formatTime} from '../components/common';
import {PageButtons, PaginationControls, defaultPageSize, usePagination} from '../components/pagination';
import type {Translator} from '../i18n';
import type {Profile, ProviderRow, RuntimeState} from '../types';

export function ProfilesPage({
    snapshot,
    providers,
    profileURL,
    dropActive,
    t,
    onProfileURLChange,
    onOpenGithub,
    onActivate,
    onEdit,
    onRename,
    onUpdateProfile,
    onDeleteProfile,
    onUpdateProvider,
    onAddSubscription,
    onToggleSubscriptionProxy,
    onDropActiveChange,
}: {
    snapshot: RuntimeState;
    providers: ProviderRow[];
    profileURL: string;
    dropActive: boolean;
    t: Translator;
    onProfileURLChange: (value: string) => void;
    onOpenGithub: () => void;
    onActivate: (id: string) => void;
    onEdit: (profile: Profile) => void;
    onRename: (profile: Profile) => void;
    onUpdateProfile: (id: string) => void;
    onDeleteProfile: (id: string) => void;
    onUpdateProvider: (name: string) => void;
    onAddSubscription: () => void;
    onToggleSubscriptionProxy: (enabled: boolean) => void;
    onDropActiveChange: (active: boolean) => void;
}) {
    const profiles = usePagination(snapshot.profiles, defaultPageSize);
    const providerPages = usePagination(providers, defaultPageSize);
    const [menu, setMenu] = useState<{ x: number; y: number; profile: Profile } | null>(null);

    return (
        <section
            className={dropActive ? 'split profileDropPage active' : 'split profileDropPage'}
            data-wails-drop-target
            onDragEnter={() => onDropActiveChange(true)}
            onDragLeave={() => onDropActiveChange(false)}
            onClick={() => setMenu(null)}
        >
            <div className="stack">
                <div className="dropHint">
                    <Upload size={16}/>{t('dropYamlHint')}
                </div>
                <article className="panel">
                    <div className="panelHead">
                        <h2>Profiles</h2>
                        <div className="rowActions">
                            <PageButtons page={profiles.safePage} pageCount={profiles.pageCount} onPage={profiles.setPage}/>
                            <PaginationControls page={profiles.safePage} pageCount={profiles.pageCount} total={profiles.total} suffix="profiles"/>
                            <button className="ghost" onClick={onOpenGithub}>
                                <Link2 size={16}/>GitHub
                            </button>
                        </div>
                    </div>
                    <div className="profileList">
                        {profiles.pageItems.map((profile) => {
                            const active = profile.id === snapshot.activeProfile || profile.name === snapshot.activeProfile;
                            return (
                                <button
                                    className={active ? 'profileRow active' : 'profileRow'}
                                    key={profile.id}
                                    onClick={() => onActivate(profile.id)}
                                    onContextMenu={(event) => {
                                        event.preventDefault();
                                        setMenu({x: event.clientX, y: event.clientY, profile});
                                    }}
                                >
                                    <div>
                                        <strong>{profile.name}</strong>
                                        <span>{profile.type} / {formatTime(profile.updatedAt, t)}</span>
                                        <SubscriptionUsage info={profile.subscription} t={t}/>
                                    </div>
                                    <div className="rowActions">
                                        <span className="activeMark">{active ? t('enable') : ''}</span>
                                    </div>
                                </button>
                            );
                        })}
                    </div>
                </article>

                <article className="panel">
                    <div className="panelHead">
                        <h2>Proxy Providers</h2>
                        <div className="rowActions">
                            <PageButtons page={providerPages.safePage} pageCount={providerPages.pageCount} onPage={providerPages.setPage}/>
                            <PaginationControls page={providerPages.safePage} pageCount={providerPages.pageCount} total={providerPages.total} suffix="providers"/>
                        </div>
                    </div>
                    <div className="table">
                        {providerPages.pageItems.map((provider) => (
                            <div className="tableRow" key={provider.name}>
                                <span>{provider.name}</span>
                                <span>{provider.vehicle || 'provider'}</span>
                                <span>{provider.proxies} {t('nodes')}</span>
                                <button onClick={() => onUpdateProvider(provider.name)}>
                                    <RefreshCcw size={15}/>{t('update')}
                                </button>
                            </div>
                        ))}
                    </div>
                </article>
            </div>

            <div className="stack">
                <article className="panel">
                    <div className="panelHead"><h2>{t('subscription')}</h2></div>
                    <Field label="URL" value={profileURL} onChange={onProfileURLChange} placeholder="https://example.com/profile.yaml"/>
                    <Toggle label={t('subscriptionProxy')} checked={snapshot.settings.subscriptionProxy} onChange={onToggleSubscriptionProxy}/>
                    <button className="primary wide" onClick={onAddSubscription}>
                        <Cloud size={17}/>{t('addSubscription')}
                    </button>
                </article>
            </div>
            {menu && (
                <div className="contextMenu" style={{left: menu.x, top: menu.y}} onClick={(event) => event.stopPropagation()}>
                    <button onClick={() => {
                        onRename(menu.profile);
                        setMenu(null);
                    }}>
                        <SquarePen size={15}/>{t('renameProfile')}
                    </button>
                    <button onClick={() => {
                        onEdit(menu.profile);
                        setMenu(null);
                    }}>
                        <SquarePen size={15}/>{t('edit')}
                    </button>
                    <button onClick={() => {
                        onUpdateProfile(menu.profile.id);
                        setMenu(null);
                    }}>
                        <RefreshCcw size={15}/>{t('update')}
                    </button>
                    <button onClick={() => {
                        onDeleteProfile(menu.profile.id);
                        setMenu(null);
                    }}>
                        <Trash2 size={15}/>{t('delete')}
                    </button>
                </div>
            )}
        </section>
    );
}
