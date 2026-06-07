import {Activity, FolderOpen, GitBranch, Globe2, PlugZap, RotateCcw, Wifi} from 'lucide-react';
import {Metric, formatBytes, formatDuration, StatusPill} from '../components/common';
import type {Translator} from '../i18n';
import type {RuntimeState} from '../types';

export function DashboardPage({snapshot, t, onRestart, onOpenDir, onOpenMihomo}: {
    snapshot: RuntimeState;
    t: Translator;
    onRestart: () => void;
    onOpenDir: () => void;
    onOpenMihomo: () => void;
}) {
    const uptime = snapshot.startedAt ? Math.max(0, Math.floor(Date.now() / 1000 - snapshot.startedAt)) : 0;
    return (
        <section className="stack">
            <div className="metricGrid">
                <Metric icon={Activity} label={t('upload')} value={formatBytes(snapshot.traffic.up)}/>
                <Metric icon={Wifi} label={t('download')} value={formatBytes(snapshot.traffic.down)}/>
                <Metric icon={PlugZap} label={t('running')} value={snapshot.running ? formatDuration(uptime) : t('stopped')}/>
                <Metric icon={Globe2} label={t('mode')} value={snapshot.settings.mode.toUpperCase()}/>
            </div>
            <article className="panel">
                <div className="panelHead">
                    <div>
                        <h2>Core</h2>
                        <span>{snapshot.settings.corePath}</span>
                    </div>
                    <StatusPill ok={snapshot.coreFound} label={snapshot.coreFound ? t('found') : t('notFound')}/>
                </div>
                <div className="quickGrid">
                    <button onClick={onRestart}><RotateCcw size={17}/>{t('restartCore')}</button>
                    <button onClick={onOpenDir}><FolderOpen size={17}/>{t('dataDirectory')}</button>
                    <button onClick={onOpenMihomo}><GitBranch size={17}/>mihomo Meta</button>
                </div>
            </article>
        </section>
    );
}
