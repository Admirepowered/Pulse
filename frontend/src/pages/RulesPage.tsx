import {StatusPill} from '../components/common';
import type {Translator} from '../i18n';
import type {RuleRow} from '../types';

export function RulesPage({rules, t}: { rules: RuleRow[]; t: Translator }) {
    return (
        <article className="panel">
            <div className="panelHead">
                <h2>Rules</h2>
                <StatusPill ok label={`${rules.length} ${t('ruleCountSuffix')}`}/>
            </div>
            <div className="ruleList">
                {rules.map((rule, index) => (
                    <div className="ruleRow" key={`${rule.type}-${rule.payload}-${index}`}>
                        <span>{rule.type}</span>
                        <strong>{rule.payload || 'MATCH'}</strong>
                        <em>{rule.proxy}</em>
                    </div>
                ))}
            </div>
        </article>
    );
}
