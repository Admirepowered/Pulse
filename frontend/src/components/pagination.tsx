import {useEffect, useMemo, useState} from 'react';
import {StatusPill} from './common';

export const defaultPageSize = 100;

export function usePagination<T>(items: T[], pageSize = defaultPageSize, maxItems = 0) {
    const visibleItems = useMemo(() => maxItems > 0 ? items.slice(0, maxItems) : items, [items, maxItems]);
    const [page, setPage] = useState(0);
    const pageCount = Math.max(1, Math.ceil(visibleItems.length / pageSize));
    const safePage = Math.min(page, pageCount - 1);
    const pageItems = useMemo(
        () => visibleItems.slice(safePage * pageSize, safePage * pageSize + pageSize),
        [visibleItems, pageSize, safePage],
    );

    useEffect(() => {
        if (page !== safePage) setPage(safePage);
    }, [page, safePage]);

    return {
        pageItems,
        safePage,
        pageCount,
        setPage,
        total: items.length,
        visibleTotal: visibleItems.length,
        capped: maxItems > 0 && items.length > maxItems,
    };
}

export function PaginationControls({page, pageCount, total, visibleTotal, capped, suffix}: {
    page: number;
    pageCount: number;
    total: number;
    visibleTotal?: number;
    capped?: boolean;
    suffix: string;
}) {
    return (
        <>
            <StatusPill ok label={`${page + 1} / ${pageCount}`}/>
            <StatusPill ok label={`${capped ? `${visibleTotal} / ${total}` : total} ${suffix}`}/>
        </>
    );
}

export function PageButtons({page, pageCount, onPage}: {
    page: number;
    pageCount: number;
    onPage: (page: number) => void;
}) {
    return (
        <>
            <button aria-label="Previous page" disabled={page <= 0} onClick={() => onPage(Math.max(0, page - 1))}>&lt;</button>
            <button aria-label="Next page" disabled={page >= pageCount - 1} onClick={() => onPage(Math.min(pageCount - 1, page + 1))}>&gt;</button>
        </>
    );
}
