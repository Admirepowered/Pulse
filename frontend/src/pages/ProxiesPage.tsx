import {Check, TimerReset} from 'lucide-react';
import {useState} from 'react';
import {SearchBox, StatusPill} from '../components/common';
import type {Translator} from '../i18n';
import type {ProxyGroup} from '../types';

export function ProxiesPage({groups, query, t, testingGroup, onQueryChange, onSelect, onTestGroup, onTestNode}: {
    groups: ProxyGroup[];
    query: string;
    t: Translator;
    testingGroup: string;
    onQueryChange: (value: string) => void;
    onSelect: (group: string, node: string) => void;
    onTestGroup: (group: string) => void;
    onTestNode: (group: string, node: string) => void;
}) {
    const [menu, setMenu] = useState<{ x: number; y: number; group: string; node: string } | null>(null);

    return (
        <section className="stack proxyPage" onClick={() => setMenu(null)}>
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
                        <button
                            className="iconButton proxyTestButton"
                            title={testingGroup === group.name ? t('testingDelay') : t('testDelay')}
                            disabled={testingGroup === group.name}
                            onClick={(event) => {
                                event.preventDefault();
                                event.stopPropagation();
                                onTestGroup(group.name);
                            }}
                        >
                            <TimerReset size={17}/>
                        </button>
                    </summary>
                    <div className="nodeGrid">
                        {group.nodes.map((node) => (
                            <button
                                className={node.name === group.now ? 'node selected' : 'node'}
                                key={`${group.name}-${node.name}`}
                                onClick={() => onSelect(group.name, node.name)}
                                onContextMenu={(event) => {
                                    event.preventDefault();
                                    setMenu({x: event.clientX, y: event.clientY, group: group.name, node: node.name});
                                }}
                            >
                                <span>{node.name}</span>
                                <small>{node.type || 'proxy'} · {node.delay >= 0 ? `${node.delay}ms` : t('pending')}</small>
                                {node.name === group.now && <Check size={16}/>}
                            </button>
                        ))}
                    </div>
                </details>
            ))}
            {menu && (
                <div className="contextMenu" style={{left: menu.x, top: menu.y}} onClick={(event) => event.stopPropagation()}>
                    <button onClick={() => {
                        onTestNode(menu.group, menu.node);
                        setMenu(null);
                    }}>
                        <TimerReset size={15}/>{t('testNode')}
                    </button>
                </div>
            )}
        </section>
    );
}
