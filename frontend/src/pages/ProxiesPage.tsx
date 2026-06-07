import {Check} from 'lucide-react';
import {SearchBox, StatusPill} from '../components/common';
import type {Translator} from '../i18n';
import type {ProxyGroup} from '../types';

export function ProxiesPage({groups, query, t, onQueryChange, onSelect}: {
    groups: ProxyGroup[];
    query: string;
    t: Translator;
    onQueryChange: (value: string) => void;
    onSelect: (group: string, node: string) => void;
}) {
    return (
        <section className="stack proxyPage">
            <SearchBox value={query} onChange={onQueryChange} placeholder={t('searchProxy')}/>
            {groups.map((group) => (
                <details className="panel proxyGroup" key={group.name}>
                    <summary className="proxyGroupHead">
                        <span className="summaryChevron" aria-hidden="true"/>
                        <div className="proxyGroupTitle">
                            <h2>{group.name}</h2>
                            <span>{group.type} · {group.now || t('notSelected')}</span>
                        </div>
                        <StatusPill ok={Boolean(group.now)} label={`${group.nodes.length} ${t('nodes')}`}/>
                    </summary>
                    <div className="nodeGrid">
                        {group.nodes.map((node) => (
                            <button
                                className={node.name === group.now ? 'node selected' : 'node'}
                                key={`${group.name}-${node.name}`}
                                onClick={() => onSelect(group.name, node.name)}
                            >
                                <span>{node.name}</span>
                                <small>{node.type || 'proxy'} · {node.delay >= 0 ? `${node.delay}ms` : t('pending')}</small>
                                {node.name === group.now && <Check size={16}/>}
                            </button>
                        ))}
                    </div>
                </details>
            ))}
        </section>
    );
}
