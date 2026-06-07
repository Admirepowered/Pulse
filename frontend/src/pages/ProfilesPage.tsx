import {Cloud, Link2, RefreshCcw, SquarePen, Trash2, Upload} from 'lucide-react';
import {Field, SubscriptionUsage, Toggle, formatTime} from '../components/common';
import {PageButtons, PaginationControls, defaultPageSize, usePagination} from '../components/pagination';
import type {Translator} from '../i18n';
import type {Profile, ProviderRow, RuntimeState} from '../types';

export function ProfilesPage({
    snapshot,
    providers,
    profileName,
    profileURL,
    dropActive,
    t,
    onProfileNameChange,
    onProfileURLChange,
    onOpenGithub,
    onActivate,
    onEdit,
    onUpdateProfile,
    onDeleteProfile,
    onUpdateProvider,
    onAddSubscription,
    onToggleSubscriptionProxy,
    onDropActiveChange,
}: {
    snapshot: RuntimeState;
    providers: ProviderRow[];
    profileName: string;
    profileURL: string;
    dropActive: boolean;
    t: Translator;
    onProfileNameChange: (value: string) => void;
    onProfileURLChange: (value: string) => void;
    onOpenGithub: () => void;
    onActivate: (id: string) => void;
    onEdit: (profile: Profile) => void;
    onUpdateProfile: (id: string) => void;
    onDeleteProfile: (id: string) => void;
    onUpdateProvider: (name: string) => void;
    onAddSubscription: () => void;
    onToggleSubscriptionProxy: (enabled: boolean) => void;
    onDropActiveChange: (active: boolean) => void;
}) {
    const profiles = usePagination(snapshot.profiles, defaultPageSize);
    const providerPages = usePagination(providers, defaultPageSize);

    return (
        <section
            className={dropActive ? 'split profileDropPage active' : 'split profileDropPage'}
            data-wails-drop-target
            onDragEnter={() => onDropActiveChange(true)}
            onDragLeave={() => onDropActiveChange(false)}
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
                                <button className={active ? 'profileRow active' : 'profileRow'} key={profile.id} onClick={() => onActivate(profile.id)}>
                                    <div>
                                        <strong>{profile.name}</strong>
                                        <span>{profile.type} / {formatTime(profile.updatedAt, t)}</span>
                                        <SubscriptionUsage info={profile.subscription} t={t}/>
                                    </div>
                                    <div className="rowActions">
                                        <span className="activeMark">{active ? t('enable') : ''}</span>
                                        <button title={t('edit')} onClick={(event) => {
                                            event.stopPropagation();
                                            onEdit(profile);
                                        }}>
                                            <SquarePen size={16}/>
                                        </button>
                                        <button title={t('update')} onClick={(event) => {
                                            event.stopPropagation();
                                            onUpdateProfile(profile.id);
                                        }}>
                                            <RefreshCcw size={16}/>
                                        </button>
                                        <button title={t('delete')} onClick={(event) => {
                                            event.stopPropagation();
                                            onDeleteProfile(profile.id);
                                        }}>
                                            <Trash2 size={16}/>
                                        </button>
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
                    <Field label={t('optionalName')} value={profileName} onChange={onProfileNameChange} placeholder={t('inferRemoteName')}/>
                    <Field label="URL" value={profileURL} onChange={onProfileURLChange} placeholder="https://example.com/profile.yaml"/>
                    <Toggle label={t('subscriptionProxy')} checked={snapshot.settings.subscriptionProxy} onChange={onToggleSubscriptionProxy}/>
                    <button className="primary wide" onClick={onAddSubscription}>
                        <Cloud size={17}/>{t('addSubscription')}
                    </button>
                </article>
            </div>
        </section>
    );
}
