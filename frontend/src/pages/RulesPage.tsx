import {StatusPill} from '../components/common';
import type {RuleRow} from '../types';

export function RulesPage({rules}: { rules: RuleRow[] }) {
    return (
        <article className="panel">
            <div className="panelHead">
                <h2>Rules</h2>
                <StatusPill ok label={`${rules.length} 条`}/>
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
