import {Check} from 'lucide-react';
import {SearchBox, StatusPill} from '../components/common';
import type {ProxyGroup} from '../types';

export function ProxiesPage({groups, query, onQueryChange, onSelect}: {
    groups: ProxyGroup[];
    query: string;
    onQueryChange: (value: string) => void;
    onSelect: (group: string, node: string) => void;
}) {
    return (
        <section className="stack proxyPage">
            <SearchBox value={query} onChange={onQueryChange} placeholder="搜索策略组、节点、类型"/>
            {groups.map((group) => (
                <details className="panel proxyGroup" key={group.name}>
                    <summary className="proxyGroupHead">
                        <span className="summaryChevron" aria-hidden="true"/>
                        <div className="proxyGroupTitle">
                            <h2>{group.name}</h2>
                            <span>{group.type} · {group.now || '未选择'}</span>
                        </div>
                        <StatusPill ok={Boolean(group.now)} label={`${group.nodes.length} 节点`}/>
                    </summary>
                    <div className="nodeGrid">
                        {group.nodes.map((node) => (
                            <button
                                className={node.name === group.now ? 'node selected' : 'node'}
                                key={`${group.name}-${node.name}`}
                                onClick={() => onSelect(group.name, node.name)}
                            >
                                <span>{node.name}</span>
                                <small>{node.type || 'proxy'} · {node.delay >= 0 ? `${node.delay}ms` : '待测'}</small>
                                {node.name === group.now && <Check size={16}/>}
                            </button>
                        ))}
                    </div>
                </details>
            ))}
        </section>
    );
}
