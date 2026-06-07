import {GripVertical, Plus, Trash2} from 'lucide-react';
import type {Translator} from '../i18n';
import type {CustomRule} from '../types';

const ruleTypes = ['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6', 'GEOIP', 'GEOSITE', 'MATCH'];

export function CustomRulesEditor({rules, policies, t, onChange}: {
    rules: CustomRule[];
    policies: string[];
    t: Translator;
    onChange: (rules: CustomRule[]) => void;
}) {
    const policyOptions = policies.length ? policies : ['DIRECT', 'REJECT'];
    const update = (index: number, patch: Partial<CustomRule>) => {
        onChange(rules.map((rule, current) => current === index ? {...rule, ...patch} : rule));
    };
    const move = (from: number, to: number) => {
        if (to < 0 || to >= rules.length) return;
        const next = [...rules];
        const [item] = next.splice(from, 1);
        next.splice(to, 0, item);
        onChange(next);
    };

    return (
        <div className="customRuleEditor">
            <div className="customRuleHeader">
                <span>{t('ruleType')}</span>
                <span>{t('rulePayload')}</span>
                <span>{t('ruleProxy')}</span>
                <span>{t('ruleOptions')}</span>
            </div>
            {rules.map((rule, index) => (
                <div
                    className="customRuleRow"
                    draggable
                    key={rule.id}
                    onDragStart={(event) => event.dataTransfer.setData('text/plain', String(index))}
                    onDragOver={(event) => event.preventDefault()}
                    onDrop={(event) => {
                        event.preventDefault();
                        move(Number(event.dataTransfer.getData('text/plain')), index);
                    }}
                >
                    <GripVertical className="dragHandle" size={16}/>
                    <select value={rule.type} onChange={(event) => update(index, {type: event.target.value})}>
                        {ruleTypes.map((type) => <option key={type} value={type}>{type}</option>)}
                    </select>
                    <input disabled={rule.type === 'MATCH'} value={rule.payload} onChange={(event) => update(index, {payload: event.target.value})}/>
                    <select value={policyOptions.includes(rule.proxy) ? rule.proxy : ''} onChange={(event) => update(index, {proxy: event.target.value})}>
                        {!policyOptions.includes(rule.proxy) && rule.proxy && <option value={rule.proxy}>{rule.proxy}</option>}
                        {policyOptions.map((policy) => <option key={policy} value={policy}>{policy}</option>)}
                    </select>
                    <label className="miniToggle">
                        <input type="checkbox" checked={rule.noResolve} onChange={(event) => update(index, {noResolve: event.target.checked})}/>
                        no-resolve
                    </label>
                    <button className="iconButton" onClick={() => onChange(rules.filter((_, current) => current !== index))}>
                        <Trash2 size={15}/>
                    </button>
                </div>
            ))}
            <button className="wide" onClick={() => onChange([...rules, newRule(policyOptions[0])])}>
                <Plus size={16}/>{t('addRule')}
            </button>
        </div>
    );
}

export function newRule(policy = 'DIRECT'): CustomRule {
    return {
        id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
        type: 'DOMAIN-SUFFIX',
        payload: '',
        proxy: policy,
        noResolve: false,
    };
}
