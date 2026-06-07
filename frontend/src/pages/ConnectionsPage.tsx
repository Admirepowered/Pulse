import {Activity, ArrowDown, ArrowUp, Cpu, X} from 'lucide-react';
import {useMemo, useState} from 'react';
import {SearchBox, formatBytes} from '../components/common';
import {PageButtons, PaginationControls, defaultPageSize, usePagination} from '../components/pagination';
import type {Translator} from '../i18n';
import type {ConnectionRow, ConnectionSnapshot} from '../types';

const maxConnections = 500;
type ConnectionSortKey = 'upload' | 'download' | 'uploadSpeed' | 'downloadSpeed';
type SortDirection = 'asc' | 'desc';

const sortOptions: { key: ConnectionSortKey; labelKey: 'upload' | 'download' | 'uploadSpeed' | 'downloadSpeed' }[] = [
    {key: 'upload', labelKey: 'upload'},
    {key: 'download', labelKey: 'download'},
    {key: 'uploadSpeed', labelKey: 'uploadSpeed'},
    {key: 'downloadSpeed', labelKey: 'downloadSpeed'},
];

export function ConnectionsPage({snapshot, connections, query, t, onQueryChange, onCloseAll, onClose}: {
    snapshot: ConnectionSnapshot;
    connections: ConnectionRow[];
    query: string;
    t: Translator;
    onQueryChange: (value: string) => void;
    onCloseAll: () => void;
    onClose: (id: string) => void;
}) {
    const [sortKey, setSortKey] = useState<ConnectionSortKey>('downloadSpeed');
    const [sortDirection, setSortDirection] = useState<SortDirection>('desc');
    const sortedConnections = useMemo(() => {
        const direction = sortDirection === 'asc' ? 1 : -1;
        return [...connections].sort((left, right) => ((left[sortKey] || 0) - (right[sortKey] || 0)) * direction);
    }, [connections, sortDirection, sortKey]);
    const pagination = usePagination(sortedConnections, defaultPageSize, maxConnections);
    const updateSort = (key: ConnectionSortKey) => {
        if (key === sortKey) {
            setSortDirection((current) => current === 'asc' ? 'desc' : 'asc');
            return;
        }
        setSortKey(key);
        setSortDirection('desc');
    };

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
                <div className="segmented sortControls">
                    {sortOptions.map((option) => (
                        <button className={sortKey === option.key ? 'active' : ''} key={option.key} onClick={() => updateSort(option.key)}>
                            {t(option.labelKey)}
                            {sortKey === option.key && (sortDirection === 'asc' ? <ArrowUp size={13}/> : <ArrowDown size={13}/>)}
                        </button>
                    ))}
                </div>
                <button className="danger" onClick={onCloseAll}>
                    <X size={16}/>{t('closeAll')}
                </button>
            </div>
            <article className="panel">
                <div className="panelHead">
                    <h2>{t('connections')}</h2>
                    <div className="rowActions">
                        <PageButtons page={pagination.safePage} pageCount={pagination.pageCount} onPage={pagination.setPage}/>
                        <PaginationControls
                            page={pagination.safePage}
                            pageCount={pagination.pageCount}
                            total={pagination.total}
                            visibleTotal={pagination.visibleTotal}
                            capped={pagination.capped}
                            suffix={t('connections')}
                        />
                    </div>
                </div>
                <div className="connectionList">
                    {pagination.pageItems.length === 0 && (
                        <div className="emptyState">{t('noConnections')}</div>
                    )}
                    {pagination.pageItems.map((item) => (
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
                            <div className="connectionTraffic">
                                <small>
                                    <ArrowUp size={13}/>{formatBytes(item.upload)}
                                    <ArrowDown size={13}/>{formatBytes(item.download)}
                                </small>
                                <small>
                                    <ArrowUp size={13}/>{formatBytes(item.uploadSpeed || 0)}/s
                                    <ArrowDown size={13}/>{formatBytes(item.downloadSpeed || 0)}/s
                                </small>
                            </div>
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
