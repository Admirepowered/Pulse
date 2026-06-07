import {ListPlus} from 'lucide-react';
import {PageButtons, PaginationControls, defaultPageSize, usePagination} from '../components/pagination';
import type {Translator} from '../i18n';
import type {Profile, RuleRow} from '../types';

export function RulesPage({rules, profiles, activeProfile, t, onEditCustomRules}: {
    rules: RuleRow[];
    profiles: Profile[];
    activeProfile: string;
    t: Translator;
    onEditCustomRules: (profile: Profile) => void;
}) {
    const pagination = usePagination(rules, defaultPageSize);
    const selectedProfile = profiles.find((profile) => profile.id === activeProfile || profile.name === activeProfile) || profiles[0];

    return (
        <article className="panel">
            <div className="panelHead">
                <h2>Rules</h2>
                <div className="rowActions">
                    <button disabled={!selectedProfile} onClick={() => selectedProfile && onEditCustomRules(selectedProfile)}>
                        <ListPlus size={16}/>{t('customRules')}
                    </button>
                    <PageButtons page={pagination.safePage} pageCount={pagination.pageCount} onPage={pagination.setPage}/>
                    <PaginationControls
                        page={pagination.safePage}
                        pageCount={pagination.pageCount}
                        total={pagination.total}
                        suffix={t('ruleCountSuffix')}
                    />
                </div>
            </div>
            <div className="ruleList">
                {pagination.pageItems.map((rule, index) => (
                    <div className="ruleRow" key={`${rule.type}-${rule.payload}-${pagination.safePage}-${index}`}>
                        <span>{rule.type}</span>
                        <strong>{rule.payload || 'MATCH'}</strong>
                        <em>{rule.proxy}</em>
                    </div>
                ))}
            </div>
        </article>
    );
}
