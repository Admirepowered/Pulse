import {Check, Cloud, Link2, ListPlus, RefreshCcw, SquarePen, Trash2, Upload} from 'lucide-react';
import {Field, SubscriptionUsage, formatTime} from '../components/common';
import {PageButtons, PaginationControls, defaultPageSize, usePagination} from '../components/pagination';
import type {Translator} from '../i18n';
import type {Profile, ProviderRow, RuntimeState} from '../types';

export function ProfilesPage({
    snapshot,
    providers,
    profileName,
    profileURL,
    importName,
    importContent,
    t,
    onProfileNameChange,
    onProfileURLChange,
    onImportNameChange,
    onImportContentChange,
    onOpenGithub,
    onActivate,
    onEdit,
    onEditRules,
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
    t: Translator;
    onProfileNameChange: (value: string) => void;
    onProfileURLChange: (value: string) => void;
    onImportNameChange: (value: string) => void;
    onImportContentChange: (value: string) => void;
    onOpenGithub: () => void;
    onActivate: (id: string) => void;
    onEdit: (profile: Profile) => void;
    onEditRules: (profile: Profile) => void;
    onUpdateProfile: (id: string) => void;
    onDeleteProfile: (id: string) => void;
    onUpdateProvider: (name: string) => void;
    onAddSubscription: () => void;
    onImportProfile: () => void;
}) {
    const profiles = usePagination(snapshot.profiles, defaultPageSize);
    const providerPages = usePagination(providers, defaultPageSize);

    return (
        <section className="split">
            <div className="stack">
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
                        {profiles.pageItems.map((profile) => (
                            <div className={profile.id === snapshot.activeProfile || profile.name === snapshot.activeProfile ? 'profileRow active' : 'profileRow'} key={profile.id}>
                                <div>
                                    <strong>{profile.name}</strong>
                                    <span>{profile.type} · {formatTime(profile.updatedAt, t)}</span>
                                    <SubscriptionUsage info={profile.subscription} t={t}/>
                                </div>
                                <div className="rowActions">
                                    <button title={t('enable')} onClick={() => onActivate(profile.id)}>
                                        <Check size={16}/>
                                    </button>
                                    <button title={t('edit')} onClick={() => onEdit(profile)}>
                                        <SquarePen size={16}/>
                                    </button>
                                    <button title={t('customRules')} onClick={() => onEditRules(profile)}>
                                        <ListPlus size={16}/>
                                    </button>
                                    <button title={t('update')} onClick={() => onUpdateProfile(profile.id)}>
                                        <RefreshCcw size={16}/>
                                    </button>
                                    <button title={t('delete')} onClick={() => onDeleteProfile(profile.id)}>
                                        <Trash2 size={16}/>
                                    </button>
                                </div>
                            </div>
                        ))}
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
                    <button className="primary wide" onClick={onAddSubscription}>
                        <Cloud size={17}/>{t('addSubscription')}
                    </button>
                </article>

                <article className="panel">
                    <div className="panelHead"><h2>{t('localYaml')}</h2></div>
                    <Field label={t('name')} value={importName} onChange={onImportNameChange}/>
                    <textarea value={importContent} onChange={(event) => onImportContentChange(event.target.value)} spellCheck={false}/>
                    <button className="wide" onClick={onImportProfile}>
                        <Upload size={17}/>{t('import')}
                    </button>
                </article>
            </div>
        </section>
    );
}
