import {useEffect, useMemo, useState} from 'react';
import {StatusPill} from '../components/common';
import type {Translator} from '../i18n';
import type {RuleRow} from '../types';

const pageSize = 100;

export function RulesPage({rules, t}: { rules: RuleRow[]; t: Translator }) {
    const [page, setPage] = useState(0);
    const pageCount = Math.max(1, Math.ceil(rules.length / pageSize));
    const safePage = Math.min(page, pageCount - 1);
    const pageRules = useMemo(() => rules.slice(safePage * pageSize, safePage * pageSize + pageSize), [rules, safePage]);

    useEffect(() => {
        if (page !== safePage) setPage(safePage);
    }, [page, safePage]);

    return (
        <article className="panel">
            <div className="panelHead">
                <h2>Rules</h2>
                <div className="rowActions">
                    <button aria-label="Previous page" disabled={safePage <= 0} onClick={() => setPage((value) => Math.max(0, value - 1))}>&lt;</button>
                    <StatusPill ok label={`${safePage + 1} / ${pageCount}`}/>
                    <button aria-label="Next page" disabled={safePage >= pageCount - 1} onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}>&gt;</button>
                    <StatusPill ok label={`${rules.length} ${t('ruleCountSuffix')}`}/>
                </div>
            </div>
            <div className="ruleList">
                {pageRules.map((rule, index) => (
                    <div className="ruleRow" key={`${rule.type}-${rule.payload}-${safePage}-${index}`}>
                        <span>{rule.type}</span>
                        <strong>{rule.payload || 'MATCH'}</strong>
                        <em>{rule.proxy}</em>
                    </div>
                ))}
            </div>
        </article>
    );
}
