import {Check, LoaderCircle, Link, Plus, TimerReset, Trash2, X} from 'lucide-react';
import {useState} from 'react';
import {SearchBox, StatusPill} from '../components/common';
import type {Translator} from '../i18n';
import type {ProxyGroup} from '../types';

export function ProxiesPage({groups, query, t, testingGroup, groupStatus, onQueryChange, onSelect, onTestGroup, onTestNode, onAddNode, onCreateChain, onRemoveNode}: {
    groups: ProxyGroup[];
    query: string;
    t: Translator;
    testingGroup: string;
    groupStatus: Record<string, 'running' | 'done' | 'failed'>;
    onQueryChange: (value: string) => void;
    onSelect: (group: string, node: string) => void;
    onTestGroup: (group: string) => void;
    onTestNode: (group: string, node: string) => void;
    onAddNode?: () => void;
    onCreateChain?: () => void;
    onRemoveNode?: (group: string, node: string) => void;
}) {
    const [menu, setMenu] = useState<{ x: number; y: number; group: string; node: string } | null>(null);

    return (
        <section className="stack proxyPage" onClick={() => setMenu(null)}>
            <div className="proxyActions">
                <SearchBox value={query} onChange={onQueryChange} placeholder={t('searchProxy')}/>
                <div className="proxyActionButtons">
                    {onAddNode && (
                        <button className="primary small" onClick={onAddNode}>
                            <Plus size={16}/>{t('addNode')}
                        </button>
                    )}
                    {onCreateChain && (
                        <button className="primary small" onClick={onCreateChain}>
                            <Link size={16}/>{t('createChain')}
                        </button>
                    )}
                </div>
            </div>
            {groups.map((group) => {
                const status = groupStatus[group.name];
                return (
                    <details className="panel proxyGroup" key={group.name}>
                        <summary className="proxyGroupHead">
                            <span className="summaryChevron" aria-hidden="true"/>
                            <div className="proxyGroupTitle">
                                <h2>{group.name}</h2>
                                <span>{group.type} 路 {group.now || t('notSelected')}</span>
                            </div>
                            <StatusPill ok={Boolean(group.now)} label={`${group.nodes.length} ${t('nodes')}`}/>
                            {status && (
                                <span
                                    className={`inlineStatus ${status}`}
                                    title={status === 'running' ? t('testingDelay') : status === 'done' ? t('delayTested') : '失败'}
                                >
                                    {status === 'running' && <LoaderCircle size={14}/>}
                                    {status === 'done' && <Check size={14}/>}
                                    {status === 'failed' && <X size={14}/>}
                                </span>
                            )}
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
                                    <small>{node.type || 'proxy'} 路 {node.delay >= 0 ? `${node.delay}ms` : t('pending')}</small>
                                    {node.name === group.now && <Check size={16}/>}
                                </button>
                            ))}
                        </div>
                    </details>
                );
            })}
            {menu && (
                <div className="contextMenu" style={{left: menu.x, top: menu.y}} onClick={(event) => event.stopPropagation()}>
                    <button onClick={() => {
                        onTestNode(menu.group, menu.node);
                        setMenu(null);
                    }}>
                        <TimerReset size={15}/>{t('testNode')}
                    </button>
                    {onRemoveNode && (
                        <button onClick={() => {
                            onRemoveNode(menu.group, menu.node);
                            setMenu(null);
                        }}>
                            <Trash2 size={15}/>{t('removeNode')}
                        </button>
                    )}
                </div>
            )}
        </section>
    );
}