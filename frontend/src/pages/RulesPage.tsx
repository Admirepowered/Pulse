import {Plus} from 'lucide-react';
import {useMemo, useState} from 'react';
import {SearchBox} from '../components/common';
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
    const [query, setQuery] = useState('');
    const filteredRules = useMemo(() => {
        const value = query.trim().toLowerCase();
        if (!value) return rules;
        return rules.filter((rule) => `${rule.type} ${rule.payload} ${rule.proxy}`.toLowerCase().includes(value));
    }, [query, rules]);
    const pagination = usePagination(filteredRules, defaultPageSize);
    const selectedProfile = profiles.find((profile) => profile.id === activeProfile || profile.name === activeProfile) || profiles[0];

    return (
        <article className="panel">
            <div className="panelHead">
                <h2>Rules</h2>
                <div className="rowActions">
                    <button className="iconButton" title={t('customRules')} disabled={!selectedProfile} onClick={() => selectedProfile && onEditCustomRules(selectedProfile)}>
                        <Plus size={16}/>
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
            <SearchBox value={query} onChange={setQuery} placeholder={t('searchRules')}/>
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
