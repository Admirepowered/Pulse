import {X} from 'lucide-react';
import {SearchBox, formatBytes} from '../components/common';
import type {ConnectionRow} from '../types';

export function ConnectionsPage({connections, query, onQueryChange, onCloseAll, onClose}: {
    connections: ConnectionRow[];
    query: string;
    onQueryChange: (value: string) => void;
    onCloseAll: () => void;
    onClose: (id: string) => void;
}) {
    return (
        <section className="stack">
            <div className="toolbar">
                <SearchBox value={query} onChange={onQueryChange} placeholder="搜索域名、规则、链路"/>
                <button className="danger" onClick={onCloseAll}>
                    <X size={16}/>全部断开
                </button>
            </div>
            <article className="panel">
                <div className="connectionList">
                    {connections.map((item) => (
                        <div className="connectionRow" key={item.id}>
                            <div>
                                <strong>{item.address || item.id}</strong>
                                <span>{item.network} · {item.rule} · {item.chains}</span>
                            </div>
                            <small>{formatBytes(item.upload)} / {formatBytes(item.download)}</small>
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
