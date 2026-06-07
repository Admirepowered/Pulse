import type {LucideIcon} from 'lucide-react';
import {Search} from 'lucide-react';
import type {SubscriptionInfo} from '../types';

export function Metric({icon: Icon, label, value}: { icon: LucideIcon; label: string; value: string }) {
    return (
        <article className="metric">
            <Icon size={20}/>
            <span>{label}</span>
            <strong>{value}</strong>
        </article>
    );
}

export function Field({label, value, onChange, type = 'text', placeholder}: {
    label: string;
    value: string;
    onChange: (value: string) => void;
    type?: string;
    placeholder?: string;
}) {
    return (
        <label className="field">
            <span>{label}</span>
            <input type={type} value={value} placeholder={placeholder} onChange={(event) => onChange(event.target.value)}/>
        </label>
    );
}

export function Toggle({label, checked, onChange}: { label: string; checked: boolean; onChange: (value: boolean) => void }) {
    return (
        <label className="toggle">
            <span>{label}</span>
            <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)}/>
        </label>
    );
}

export function SearchBox({value, onChange, placeholder}: { value: string; onChange: (value: string) => void; placeholder: string }) {
    return (
        <label className="search">
            <Search size={17}/>
            <input value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder}/>
        </label>
    );
}

export function StatusPill({ok, label}: { ok: boolean; label: string }) {
    return <span className={ok ? 'pill ok' : 'pill'}>{label}</span>;
}

export function SubscriptionUsage({info}: { info?: SubscriptionInfo }) {
    if (!info || !info.total) return null;
    const used = Math.max(0, (info.upload || 0) + (info.download || 0));
    const percent = Math.min(100, Math.max(0, (used / info.total) * 100));
    return (
        <div className="subscriptionUsage">
            <div>
                <span>{formatBytes(used)} / {formatBytes(info.total)}</span>
                <span>{info.expire ? `到期 ${formatDate(info.expire)}` : '未提供到期时间'}</span>
            </div>
            <div className="usageBar" title={`${percent.toFixed(1)}%`}>
                <span style={{width: `${percent}%`}}/>
            </div>
        </div>
    );
}

export function noticeError(value: string) {
    const lower = value.toLowerCase();
    return lower.includes('error') || lower.includes('not') || lower.includes('empty') || lower.includes('failed');
}

export function formatBytes(bytes: number) {
    if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let value = bytes;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
        value /= 1024;
        unit += 1;
    }
    return `${value.toFixed(value >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

export function formatDuration(seconds: number) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const rest = seconds % 60;
    if (hours) return `${hours}h ${minutes}m`;
    if (minutes) return `${minutes}m ${rest}s`;
    return `${rest}s`;
}

export function formatTime(seconds: number) {
    if (!seconds) return '未更新';
    return new Date(seconds * 1000).toLocaleString();
}

export function formatDate(seconds: number) {
    if (!seconds) return '未知';
    return new Date(seconds * 1000).toLocaleDateString();
}

export function formatClock(seconds: number) {
    if (!seconds) return '--:--:--';
    return new Date(seconds * 1000).toLocaleTimeString();
}
