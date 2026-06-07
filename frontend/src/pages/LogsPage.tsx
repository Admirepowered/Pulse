import {formatClock} from '../components/common';
import {PageButtons, PaginationControls, defaultPageSize, usePagination} from '../components/pagination';
import type {LogLine} from '../types';

const maxLogs = 500;

export function LogsPage({logs}: { logs: LogLine[] }) {
    const orderedLogs = logs.slice().reverse();
    const pagination = usePagination(orderedLogs, defaultPageSize, maxLogs);

    return (
        <article className="panel logs">
            <div className="panelHead">
                <h2>Logs</h2>
                <div className="rowActions">
                    <PageButtons page={pagination.safePage} pageCount={pagination.pageCount} onPage={pagination.setPage}/>
                    <PaginationControls
                        page={pagination.safePage}
                        pageCount={pagination.pageCount}
                        total={pagination.total}
                        visibleTotal={pagination.visibleTotal}
                        capped={pagination.capped}
                        suffix="logs"
                    />
                </div>
            </div>
            {pagination.pageItems.map((line, index) => (
                <div className={`logLine ${line.level}`} key={`${line.time}-${index}`}>
                    <span>{formatClock(line.time)}</span>
                    <strong>{line.level}</strong>
                    <p>{line.message}</p>
                </div>
            ))}
        </article>
    );
}
