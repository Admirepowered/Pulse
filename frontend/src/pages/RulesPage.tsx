import {PageButtons, PaginationControls, defaultPageSize, usePagination} from '../components/pagination';
import type {Translator} from '../i18n';
import type {RuleRow} from '../types';

export function RulesPage({rules, t}: { rules: RuleRow[]; t: Translator }) {
    const pagination = usePagination(rules, defaultPageSize);

    return (
        <article className="panel">
            <div className="panelHead">
                <h2>Rules</h2>
                <div className="rowActions">
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
