import {Check, Cloud, Copy, Link2, LoaderCircle, RefreshCcw, Route, SquarePen, Trash2, Upload, WifiOff, X} from 'lucide-react';
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
    updatingProviders,
    t,
    onProfileURLChange,
    onOpenGithub,
    onActivate,
    onEdit,
    onRename,
    onUpdateSource,
    onUpdateProfile,
    onCopySource,
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
    updatingProviders: Record<string, 'running' | 'done' | 'failed'>;
    t: Translator;
    onProfileURLChange: (value: string) => void;
    onOpenGithub: () => void;
    onActivate: (id: string) => void;
    onEdit: (profile: Profile) => void;
    onRename: (profile: Profile, name: string) => void;
    onUpdateSource: (profile: Profile, source: string) => void;
    onUpdateProfile: (id: string, useProxy?: boolean) => void;
    onCopySource: (source: string) => void;
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
    const [editingSource, setEditingSource] = useState<{ id: string; value: string } | null>(null);
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
    const startSourceEdit = (profile: Profile) => {
        setMenu(null);
        setEditingSource({id: profile.id, value: profile.source || ''});
    };
    const commitSource = (profile: Profile) => {
        if (!editingSource || editingSource.id !== profile.id) return;
        const next = editingSource.value.trim();
        setEditingSource(null);
        if (next && next !== profile.source) onUpdateSource(profile, next);
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
                                        {profile.source && editingSource?.id === profile.id && (
                                                <input
                                                    className="profileSourceInput"
                                                    autoFocus
                                                    value={editingSource.value}
                                                    onClick={(event) => event.stopPropagation()}
                                                    onChange={(event) => setEditingSource({id: profile.id, value: event.target.value})}
                                                    onBlur={() => commitSource(profile)}
                                                    onKeyDown={(event) => {
                                                        if (event.key === 'Enter') event.currentTarget.blur();
                                                        if (event.key === 'Escape') setEditingSource(null);
                                                    }}
                                                />
                                        )}
                                        <SubscriptionUsage info={profile.subscription} t={t}/>
                                    </div>
                                    <div className="rowActions">
                                        <span className="activeMark">{active ? t('enable') : ''}</span>
                                        <button
                                            className={`iconButton stateButton ${status || ''}`}
                                            title={status === 'running' ? '正在更新' : status === 'done' ? '已更新' : status === 'failed' ? '更新失败' : t('update')}
                                            disabled={status === 'running'}
                                            onClick={(event) => {
                                                event.stopPropagation();
                                                onUpdateProfile(profile.id);
                                            }}
                                        >
                                            <StatusIcon status={status}/>
                                        </button>
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
                                <button
                                    className={`iconButton stateButton ${updatingProviders[provider.name] || ''}`}
                                    title={updatingProviders[provider.name] === 'running' ? '正在更新' : updatingProviders[provider.name] === 'done' ? '已更新' : updatingProviders[provider.name] === 'failed' ? '更新失败' : t('update')}
                                    disabled={updatingProviders[provider.name] === 'running'}
                                    onClick={() => onUpdateProvider(provider.name)}
                                >
                                    <StatusIcon status={updatingProviders[provider.name]}/>
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
                    {menu.profile.source && (
                        <button onClick={() => startSourceEdit(menu.profile)}>
                            <Link2 size={15}/>{t('editURL')}
                        </button>
                    )}
                    {menu.profile.source && (
                        <button onClick={() => {
                            onCopySource(menu.profile.source);
                            setMenu(null);
                        }}>
                            <Copy size={15}/>{t('copyURL')}
                        </button>
                    )}
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
                    {menu.profile.source && (
                        <button onClick={() => {
                            onUpdateProfile(menu.profile.id, true);
                            setMenu(null);
                        }}>
                            <Route size={15}/>{t('updateWithProxy')}
                        </button>
                    )}
                    {menu.profile.source && (
                        <button onClick={() => {
                            onUpdateProfile(menu.profile.id, false);
                            setMenu(null);
                        }}>
                            <WifiOff size={15}/>{t('updateDirect')}
                        </button>
                    )}
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

function StatusIcon({status}: { status?: 'running' | 'done' | 'failed' }) {
    if (status === 'running') return <LoaderCircle size={15}/>;
    if (status === 'done') return <Check size={15}/>;
    if (status === 'failed') return <X size={15}/>;
    return <RefreshCcw size={15}/>;
}
