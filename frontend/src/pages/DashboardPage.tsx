import {Activity, FolderOpen, GitBranch, Globe2, PlugZap, RotateCcw, Wifi} from 'lucide-react';
import {useEffect, useState} from 'react';
import {Metric, formatBytes, formatDuration, StatusPill} from '../components/common';
import type {Translator} from '../i18n';
import type {ConnectionSnapshot, RuntimeState} from '../types';
import {NetworkSpeedCard} from './dashboard/NetworkSpeedCard';

const maxSpeedPoints = 32;

export function DashboardPage({snapshot, connections, t, onRestart, onOpenDir, onOpenMihomo}: {
    snapshot: RuntimeState;
    connections: ConnectionSnapshot;
    t: Translator;
    onRestart: () => void;
    onOpenDir: () => void;
    onOpenMihomo: () => void;
}) {
    const [speedPoints, setSpeedPoints] = useState<number[]>([]);
    const uptime = snapshot.startedAt ? Math.max(0, Math.floor(Date.now() / 1000 - snapshot.startedAt)) : 0;
    const totalTraffic = (connections.uploadTotal || 0) + (connections.downloadTotal || 0);
    const coreLabel = snapshot.settings.coreMode === 'embedded' ? t('embedded') : snapshot.settings.corePath;

    useEffect(() => {
        const totalSpeed = Math.max(0, (snapshot.traffic.up || 0) + (snapshot.traffic.down || 0));
        setSpeedPoints((current) => [...current.slice(-(maxSpeedPoints - 1)), totalSpeed]);
    }, [snapshot.traffic.up, snapshot.traffic.down]);

    return (
        <section className="stack">
            <NetworkSpeedCard traffic={snapshot.traffic} points={speedPoints} t={t}/>
            <div className="metricGrid">
                <Metric icon={Activity} label={t('upload')} value={formatBytes(snapshot.traffic.up)}/>
                <Metric icon={Wifi} label={t('download')} value={formatBytes(snapshot.traffic.down)}/>
                <Metric icon={Activity} label={t('totalTraffic')} value={formatBytes(totalTraffic)}/>
                <Metric icon={PlugZap} label={t('running')} value={snapshot.running ? formatDuration(uptime) : t('stopped')}/>
                <Metric icon={Globe2} label={t('mode')} value={snapshot.settings.mode.toUpperCase()}/>
            </div>
            <article className="panel">
                <div className="panelHead">
                    <div>
                        <h2>Core</h2>
                        <span>{coreLabel}</span>
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
