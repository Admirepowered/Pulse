import {Activity, FolderOpen, GitBranch, Globe2, PlugZap, RotateCcw, Wifi} from 'lucide-react';
import {Metric, formatBytes, formatDuration, StatusPill} from '../components/common';
import type {RuntimeState} from '../types';

export function DashboardPage({snapshot, onRestart, onOpenDir, onOpenMihomo}: {
    snapshot: RuntimeState;
    onRestart: () => void;
    onOpenDir: () => void;
    onOpenMihomo: () => void;
}) {
    const uptime = snapshot.startedAt ? Math.max(0, Math.floor(Date.now() / 1000 - snapshot.startedAt)) : 0;
    return (
        <section className="stack">
            <div className="metricGrid">
                <Metric icon={Activity} label="上行" value={formatBytes(snapshot.traffic.up)}/>
                <Metric icon={Wifi} label="下行" value={formatBytes(snapshot.traffic.down)}/>
                <Metric icon={PlugZap} label="运行" value={snapshot.running ? formatDuration(uptime) : '停止'}/>
                <Metric icon={Globe2} label="模式" value={snapshot.settings.mode.toUpperCase()}/>
            </div>
            <article className="panel">
                <div className="panelHead">
                    <div>
                        <h2>Core</h2>
                        <span>{snapshot.settings.corePath}</span>
                    </div>
                    <StatusPill ok={snapshot.coreFound} label={snapshot.coreFound ? '已找到' : '未找到'}/>
                </div>
                <div className="quickGrid">
                    <button onClick={onRestart}><RotateCcw size={17}/>重启核心</button>
                    <button onClick={onOpenDir}><FolderOpen size={17}/>数据目录</button>
                    <button onClick={onOpenMihomo}><GitBranch size={17}/>mihomo Meta</button>
                </div>
            </article>
            <article className="panel">
                <div className="panelHead"><h2>最近日志</h2></div>
                <div className="compactLogs">
                    {snapshot.recentLogs.slice(-8).reverse().map((line, index) => (
                        <div key={`${line.time}-${index}`}>{line.message}</div>
                    ))}
                </div>
            </article>
        </section>
    );
}
