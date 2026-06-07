import {Activity, ArrowDown, ArrowUp, Cpu, X} from 'lucide-react';
import {SearchBox, formatBytes} from '../components/common';
import type {Translator} from '../i18n';
import type {ConnectionRow, ConnectionSnapshot} from '../types';

export function ConnectionsPage({snapshot, connections, query, t, onQueryChange, onCloseAll, onClose}: {
    snapshot: ConnectionSnapshot;
    connections: ConnectionRow[];
    query: string;
    t: Translator;
    onQueryChange: (value: string) => void;
    onCloseAll: () => void;
    onClose: (id: string) => void;
}) {
    return (
        <section className="stack">
            <div className="connectionStats">
                <div className="metric compact">
                    <Activity size={18}/>
                    <span>{t('currentConnections')}</span>
                    <strong>{snapshot.connections?.length || 0}</strong>
                </div>
                <div className="metric compact">
                    <ArrowUp size={18}/>
                    <span>{t('uploadSpeed')}</span>
                    <strong>{formatBytes(snapshot.uploadSpeed || 0)}/s</strong>
                </div>
                <div className="metric compact">
                    <ArrowDown size={18}/>
                    <span>{t('downloadSpeed')}</span>
                    <strong>{formatBytes(snapshot.downloadSpeed || 0)}/s</strong>
                </div>
                <div className="metric compact">
                    <Cpu size={18}/>
                    <span>{t('totalMemory')}</span>
                    <strong>{formatBytes((snapshot.uploadTotal || 0) + (snapshot.downloadTotal || 0))} / {formatBytes(snapshot.memory || 0)}</strong>
                </div>
            </div>
            <div className="toolbar">
                <SearchBox value={query} onChange={onQueryChange} placeholder={t('searchConnections')}/>
                <button className="danger" onClick={onCloseAll}>
                    <X size={16}/>{t('closeAll')}
                </button>
            </div>
            <article className="panel">
                <div className="connectionList">
                    {connections.length === 0 && (
                        <div className="emptyState">{t('noConnections')}</div>
                    )}
                    {connections.map((item) => (
                        <div className="connectionRow" key={item.id}>
                            <div>
                                <strong>{item.address || item.destinationIp || item.id}</strong>
                                <span>
                                    {item.destinationIp && item.destinationIp !== item.address ? `${t('destination')} ${item.destinationIp} · ` : ''}
                                    {item.source ? `${t('source')} ${item.source} · ` : ''}
                                    {item.process ? `${item.process} · ` : ''}
                                    {item.network} · {item.rule} · {item.chains}
                                </span>
                            </div>
                            <small>
                                <ArrowUp size={13}/>{formatBytes(item.upload)}
                                <ArrowDown size={13}/>{formatBytes(item.download)}
                            </small>
                            <button onClick={() => onClose(item.id)}>
                                <X size={16}/>
                            </button>
                        </div>
                    ))}
                </div>
            </article>
        </section>
    );
}
