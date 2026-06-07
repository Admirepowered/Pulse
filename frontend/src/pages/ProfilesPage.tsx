import {Check, Cloud, Link2, LoaderCircle, RefreshCcw, SquarePen, Trash2, Upload, X} from 'lucide-react';
import type {CSSProperties, KeyboardEvent} from 'react';
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
    updatingProfiles,
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
    updatingProfiles: Record<string, 'running' | 'done' | 'failed'>;
    t: Translator;
    onProfileURLChange: (value: string) => void;
    onOpenGithub: () => void;
    onActivate: (id: string) => void;
    onEdit: (profile: Profile) => void;
    onRename: (profile: Profile, name: string) => void;
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
    const [renaming, setRenaming] = useState<{ id: string; value: string } | null>(null);
    const startRename = (profile: Profile) => {
        setMenu(null);
        setRenaming({id: profile.id, value: profile.name});
    };
    const commitRename = (profile: Profile) => {
        if (!renaming || renaming.id !== profile.id) return;
        const next = renaming.value.trim();
        setRenaming(null);
        if (next && next !== profile.name) onRename(profile, next);
    };

    return (
        <section
            className={dropActive ? 'split profileDropPage active' : 'split profileDropPage'}
            data-wails-drop-target
            style={{'--wails-drop-target': 'drop'} as CSSProperties}
            onDragEnter={() => onDropActiveChange(true)}
            onDragLeave={() => onDropActiveChange(false)}
            onDragOver={(event) => {
                event.preventDefault();
                onDropActiveChange(true);
            }}
            onDrop={() => onDropActiveChange(false)}
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
                            const status = updatingProfiles[profile.id];
                            return (
                                <div
                                    role="button"
                                    tabIndex={0}
                                    className={active ? 'profileRow active' : 'profileRow'}
                                    key={profile.id}
                                    onClick={() => onActivate(profile.id)}
                                    onKeyDown={(event: KeyboardEvent<HTMLDivElement>) => {
                                        if (event.target instanceof HTMLInputElement) return;
                                        if (event.key === 'Enter' || event.key === ' ') onActivate(profile.id);
                                    }}
                                    onContextMenu={(event) => {
                                        event.preventDefault();
                                        setMenu({x: event.clientX, y: event.clientY, profile});
                                    }}
                                >
                                    <div className="profileSummary">
                                        {renaming?.id === profile.id ? (
                                            <input
                                                className="profileNameInput"
                                                autoFocus
                                                value={renaming.value}
                                                onClick={(event) => event.stopPropagation()}
                                                onChange={(event) => setRenaming({id: profile.id, value: event.target.value})}
                                                onBlur={() => commitRename(profile)}
                                                onKeyDown={(event) => {
                                                    if (event.key === 'Enter') event.currentTarget.blur();
                                                    if (event.key === 'Escape') setRenaming(null);
                                                }}
                                            />
                                        ) : (
                                            <strong>{profile.name}</strong>
                                        )}
                                        <label className="profileMeta">
                                            <span>{profile.type}</span>
                                            <span>{formatTime(profile.updatedAt, t)}</span>
                                        </label>
                                        <SubscriptionUsage info={profile.subscription} t={t}/>
                                    </div>
                                    <div className="rowActions">
                                        <span className="activeMark">{active ? t('enable') : ''}</span>
                                        {status && (
                                            <span
                                                className={`inlineStatus ${status}`}
                                                title={status === 'running' ? '正在更新' : status === 'done' ? '已更新' : '更新失败'}
                                            >
                                                {status === 'running' && <LoaderCircle size={14}/>}
                                                {status === 'done' && <Check size={14}/>}
                                                {status === 'failed' && <X size={14}/>}
                                            </span>
                                        )}
                                    </div>
                                </div>
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
                        startRename(menu.profile);
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
