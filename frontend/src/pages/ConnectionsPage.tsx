import {Activity, ArrowDown, ArrowUp, Cpu, MoreHorizontal} from 'lucide-react';
import {useMemo, useState} from 'react';
import {SearchBox, formatBytes, formatDuration} from '../components/common';
import {PageButtons, PaginationControls, defaultPageSize, usePagination} from '../components/pagination';
import type {Translator} from '../i18n';
import type {ConnectionRow, ConnectionSnapshot} from '../types';

const maxConnections = 500;
type ConnectionTab = 'active' | 'closed';
type ConnectionSort = '' | 'download-asc' | 'download-desc' | 'downloadSpeed-asc' | 'downloadSpeed-desc';

const sortOptions: { value: ConnectionSort; label: string }[] = [
    {value: '', label: '默认排序'},
    {value: 'download-asc', label: '下载总量升序'},
    {value: 'download-desc', label: '下载总量降序'},
    {value: 'downloadSpeed-asc', label: '下载速度升序'},
    {value: 'downloadSpeed-desc', label: '下载速度降序'},
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
    const [tab, setTab] = useState<ConnectionTab>('active');
    const [sort, setSort] = useState<ConnectionSort>('');
    const [menu, setMenu] = useState<{ x: number; y: number; id: string } | null>(null);
    const rows = tab === 'active' ? connections : (snapshot.closed || []);
    const filteredRows = useMemo(() => {
        const value = query.trim().toLowerCase();
        if (!value) return rows;
        return rows.filter((item) => `${item.address} ${item.destinationIp} ${item.source} ${item.process} ${item.rule} ${item.chains}`.toLowerCase().includes(value));
    }, [query, rows]);
    const sortedRows = useMemo(() => {
        if (!sort) return filteredRows;
        const [key, direction] = sort.split('-') as ['download' | 'downloadSpeed', 'asc' | 'desc'];
        const multiplier = direction === 'asc' ? 1 : -1;
        return [...filteredRows].sort((left, right) => {
            const diff = (left[key] || 0) - (right[key] || 0);
            return diff === 0 ? 0 : diff * multiplier;
        });
    }, [filteredRows, sort]);
    const pagination = usePagination(sortedRows, defaultPageSize, maxConnections);

    return (
        <section className="stack" onClick={() => setMenu(null)}>
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
                <select className="selectControl" value={sort} onChange={(event) => setSort(event.target.value as ConnectionSort)}>
                    {sortOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
                </select>
                <div className="connectionTabs">
                    <button className={tab === 'active' ? 'active' : ''} onClick={() => setTab('active')}>
                        {t('running')} <span>{connections.length}</span>
                    </button>
                    <button className={tab === 'closed' ? 'active' : ''} onClick={() => setTab('closed')}>
                        {t('stopped')} <span>{snapshot.closed?.length || 0}</span>
                    </button>
                </div>
                {tab === 'active' && (
                    <button className="danger" onClick={onCloseAll}>{t('closeAll')}</button>
                )}
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
                    {pagination.pageItems.length === 0 && <div className="emptyState">{t('noConnections')}</div>}
                    {pagination.pageItems.map((item) => (
                        <div
                            className="connectionRow"
                            key={`${tab}-${item.id}-${item.closedAt || 0}`}
                            onContextMenu={(event) => {
                                event.preventDefault();
                                if (tab === 'active') setMenu({x: event.clientX, y: event.clientY, id: item.id});
                            }}
                        >
                            <div>
                                <strong>{item.address || item.destinationIp || item.id}</strong>
                                <span>
                                    {item.destinationIp && item.destinationIp !== item.address ? `${t('destination')} ${item.destinationIp} · ` : ''}
                                    {item.source ? `${t('source')} ${item.source} · ` : ''}
                                    {item.process ? `${item.process} · ` : ''}
                                    {item.network} · {item.rule || '-'} · {item.chains || '-'}
                                </span>
                            </div>
                            <div className="connectionTraffic">
                                <small><ArrowDown size={13}/>下载总量 {formatBytes(item.download)}</small>
                                <small><ArrowDown size={13}/>下载速度 {formatBytes(item.downloadSpeed || 0)}/s</small>
                                <small><ArrowUp size={13}/>上传总量 {formatBytes(item.upload)}</small>
                                <small><ArrowUp size={13}/>上传速度 {formatBytes(item.uploadSpeed || 0)}/s</small>
                            </div>
                            <div className="connectionMeta">
                                <small>{tab === 'closed' ? '已断开' : '已连接'} {connectionAge(item, tab)}</small>
                                {tab === 'active' && <MoreHorizontal size={16}/>}
                            </div>
                        </div>
                    ))}
                </div>
            </article>
            {menu && (
                <div className="contextMenu" style={{left: menu.x, top: menu.y}} onClick={(event) => event.stopPropagation()}>
                    <button onClick={() => {
                        onClose(menu.id);
                        setMenu(null);
                    }}>
                        结束连接
                    </button>
                </div>
            )}
        </section>
    );
}

function connectionAge(item: ConnectionRow, tab: ConnectionTab) {
    if (tab === 'closed' && item.closedAt) return formatDuration(Math.max(0, Math.floor(Date.now() / 1000) - item.closedAt));
    const start = Date.parse(item.start || '');
    if (!start) return '-';
    return formatDuration(Math.max(0, Math.floor((Date.now() - start) / 1000)));
}
